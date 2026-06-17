package com.goc.demo;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.goc.crypto.ec.ECCrypto;
import com.goc.ledger.ec.ECLedger;
import com.goc.zkp.equivalence.ec.ECCiphertextEquivalenceProof;
import com.goc.zkp.equivalence.ec.ECCiphertextEquivalenceProver;
import com.goc.zkp.range.bitdecomposition.ec.ECBitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.ec.ECBitDecompositionRangeVerifier;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeWitness;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * ElGamal over Ristretto255 (Curve25519) implementation of the ledger
 * demo session — the fast, practical backend.
 */
public class EcLedgerSession implements LedgerService.Session {

    private static final String[] NAMES = {"Alice", "Bob", "Carol"};
    private static final long[]   MINTS = {20, 10, 5};
    private static final long     DECRYPT_BOUND = 1L << 16; // balances ≪ this

    private final ECCryptoGroup group;
    private final ECCrypto crypto;
    private final ECBitDecompositionRangeProver prover;
    private final ECCiphertextEquivalenceProver equivalenceProver;
    private final ECLedger ledger;
    private final Scalar sk;
    private final RistrettoElement pk;
    private final int bitLength;

    public EcLedgerSession(int bitLength) {
        this.bitLength = bitLength;
        this.group  = new ECCryptoGroup();
        this.crypto = new ECCrypto(group);

        ECKeyPair kp = crypto.keyGen();
        this.sk = kp.secretKey;
        this.pk = kp.publicKey;

        this.prover            = new ECBitDecompositionRangeProver(group, crypto, bitLength);
        this.equivalenceProver = new ECCiphertextEquivalenceProver(group, crypto);
        var verifier           = new ECBitDecompositionRangeVerifier(group, bitLength);

        this.ledger = new ECLedger(group, NAMES.length, verifier);
        for (int i = 0; i < NAMES.length; i++) {
            ledger.registerAccount(i, pk);
            ledger.mint(i, crypto.encrypt(MINTS[i], pk));
        }
    }

    @Override public String backend() { return "EC"; }
    @Override public int bitLength()  { return bitLength; }

    @Override
    public List<LedgerService.AccountView> accounts() {
        List<LedgerService.AccountView> out = new ArrayList<>();
        for (int i = 0; i < NAMES.length; i++) {
            ECCiphertext bal = ledger.computeBalance(i);
            out.add(new LedgerService.AccountView(
                    i, NAMES[i],
                    bal == null ? "—" : hex(bal.c1),
                    bal == null ? "—" : hex(bal.c2),
                    decrypt(bal)));
        }
        return out;
    }

    @Override
    public TransferOutcome transfer(int sender, int receiver, long amount, String mode) {
        List<String> log = new ArrayList<>();
        long maxValue = (1L << bitLength) - 1;
        if (amount > maxValue) {
            log.add("Amount " + amount + " is larger than this range proof can handle (2^"
                    + bitLength + "−1 = " + maxValue + ").");
            return new TransferOutcome(false, log);
        }

        ECCiphertext current = ledger.computeBalance(sender);
        long currentValue    = decrypt(current);
        log.add("Step 1: " + NAMES[sender] + "'s current balance is " + currentValue
                + " (decrypted only with the demo key).");
        log.add("        The network sees only the encrypted form: Enc(c1=" + shortHex(current.c1)
                + ", c2=" + shortHex(current.c2) + ").");

        try {
            return switch (mode.toUpperCase()) {
                case "NORMAL"      -> normal(sender, receiver, amount, currentValue, current, log);
                case "OVERSPEND"   -> overspend(sender, receiver, amount, currentValue, current, log);
                case "IMPERSONATE" -> impersonate(sender, receiver, amount, current, log);
                case "TAMPER"      -> tamper(sender, receiver, amount, currentValue, current, log);
                default -> {
                    log.add("Unknown mode: " + mode);
                    yield new TransferOutcome(false, log);
                }
            };
        } catch (Exception e) {
            log.add("Could not build the transaction proof: " + e.getMessage());
            return new TransferOutcome(false, log);
        }
    }

    // ---------------------------------------------------------------- modes

    private TransferOutcome normal(int sender, int receiver, long amount,
                                   long currentValue, ECCiphertext current, List<String> log) {
        long newValue = currentValue - amount;
        if (newValue < 0) {
            log.add("Honest path: the new balance would be " + newValue + " < 0, so "
                    + NAMES[sender] + " is trying to send more than they have. A negative value "
                    + "has no valid range proof, so the transfer cannot be built. (Try the "
                    + "'Attack: fake new balance' mode to see how a lie is caught.)");
            return new TransferOutcome(false, log);
        }
        log.add("Step 2: " + NAMES[sender] + " sends " + amount + ", so the new balance will be " + newValue + ".");
        ECRangeProof amountProof     = prover.prove(new ECRangeWitness(BigInteger.valueOf(amount), sk, pk));
        ECRangeProof newBalanceProof = prover.prove(new ECRangeWitness(BigInteger.valueOf(newValue), sk, pk));
        log.add("Step 3: Range proofs are built for the amount (" + amount + " ≥ 0) and the new balance (" + newValue + " ≥ 0).");

        ECCiphertext expected = current.subtract(amountProof.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = equivalenceProver.prove(sk, pk, expected, newBalanceProof.getEncryptedValue());
        log.add("Step 4: An equivalence proof is built: new balance == current − amount (without showing the numbers).");

        boolean accepted = ledger.submitTransaction(sender, receiver,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof, eq);
        log.add(accepted
                ? "Result: ACCEPT ✓ — " + NAMES[sender] + " → " + NAMES[receiver] + " transferred " + amount + "."
                : "Result: REJECT ✗");
        return new TransferOutcome(accepted, log);
    }

    private TransferOutcome overspend(int sender, int receiver, long amount,
                                      long currentValue, ECCiphertext current, List<String> log) {
        long fake       = currentValue;             // lie: "my balance did not change"
        long honestNew  = currentValue - amount;    // what it should actually be
        log.add("Step 2: Cheat — here " + NAMES[sender] + " herself is dishonest. She sends " + amount
                + " to the receiver, but tells the ledger her own balance does NOT change (still "
                + fake + "), so she keeps her tokens. This would create money from nothing.");
        log.add("Step 3: She can even build a valid range proof for this false balance (" + fake + " ≥ 0).");

        ECRangeProof amountProof  = prover.prove(new ECRangeWitness(BigInteger.valueOf(amount), sk, pk));
        ECRangeProof fakeBalProof = prover.prove(new ECRangeWitness(BigInteger.valueOf(fake), sk, pk));

        ECCiphertext expected = current.subtract(amountProof.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = equivalenceProver.prove(sk, pk, expected, fakeBalProof.getEncryptedValue());
        log.add("Step 4: But the ledger checks the equivalence proof: the new balance must equal current − amount = "
                + currentValue + " − " + amount + " = " + honestNew + ". She claimed " + fake + ".");

        boolean accepted = ledger.submitTransaction(sender, receiver,
                amountProof.getEncryptedValue(), amountProof,
                fakeBalProof.getEncryptedValue(), fakeBalProof, eq);
        log.add(accepted
                ? "Result: ACCEPT — unexpected!"
                : "Result: REJECT ✗ — the equivalence proof fails because " + fake + " ≠ " + honestNew + ". She cannot keep her tokens.");
        return new TransferOutcome(accepted, log);
    }

    private TransferOutcome impersonate(int sender, int receiver, long amount,
                                        ECCiphertext current, List<String> log) {
        ECKeyPair attacker = crypto.keyGen();
        log.add("Step 2: Attack — an attacker (not " + NAMES[sender] + ") tries to send as "
                + NAMES[sender] + ", using their own key.");

        ECRangeProof amountProof     = prover.prove(new ECRangeWitness(BigInteger.valueOf(amount), attacker.secretKey, attacker.publicKey));
        ECRangeProof newBalanceProof = prover.prove(new ECRangeWitness(BigInteger.valueOf(amount), attacker.secretKey, attacker.publicKey));
        log.add("Step 3: All proofs are built with the attacker's key, not " + NAMES[sender] + "'s.");

        ECCiphertext expected = current.subtract(amountProof.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = equivalenceProver.prove(attacker.secretKey, attacker.publicKey,
                expected, newBalanceProof.getEncryptedValue());

        boolean accepted = ledger.submitTransaction(sender, receiver,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof, eq);
        log.add(accepted
                ? "Result: ACCEPT — unexpected!"
                : "Result: REJECT ✗ — the proofs do not match " + NAMES[sender] + "'s registered key (binding proof).");
        return new TransferOutcome(accepted, log);
    }

    private TransferOutcome tamper(int sender, int receiver, long amount,
                                   long currentValue, ECCiphertext current, List<String> log) {
        long newValue = currentValue - amount;
        if (newValue < 0) {
            log.add("The tamper scenario needs enough balance (new balance ≥ 0). Try a smaller amount.");
            return new TransferOutcome(false, log);
        }
        log.add("Step 2: A real, valid transfer of " + amount + " is built (new balance " + newValue + ") — every proof is correct and the key is " + NAMES[sender] + "'s own.");
        ECRangeProof amountProof     = prover.prove(new ECRangeWitness(BigInteger.valueOf(amount), sk, pk));
        ECRangeProof newBalanceProof = prover.prove(new ECRangeWitness(BigInteger.valueOf(newValue), sk, pk));
        ECCiphertext expected = current.subtract(amountProof.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = equivalenceProver.prove(sk, pk, expected, newBalanceProof.getEncryptedValue());

        log.add("Step 3: Tamper — after the proof is built, one number inside it (the equivalence response s) is changed by +1. Only the proof is edited; the key is still correct.");
        ECCiphertextEquivalenceProof tampered = new ECCiphertextEquivalenceProof(
                eq.commitmentK1(), eq.commitmentK2(), eq.responseS().add(Scalar.ONE));

        boolean accepted = ledger.submitTransaction(sender, receiver,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof, tampered);
        log.add(accepted
                ? "Result: ACCEPT — unexpected!"
                : "Result: REJECT ✗ — the verifier recomputes the Fiat–Shamir challenge and sees the proof no longer fits. Even a 1-number change breaks it.");
        return new TransferOutcome(accepted, log);
    }

    // -------------------------------------------------------------- helpers

    private long decrypt(ECCiphertext ct) {
        if (ct == null) return 0;
        RistrettoElement gm = crypto.decryptToGroupElement(ct, sk);
        // Demo balances are tiny (conserved sum of mints); cap the discrete-log
        // search independently of bitLength so 32-bit proofs stay snappy.
        return crypto.babyStepGiantStepLog(gm, DECRYPT_BOUND);
    }

    private static String hex(RistrettoElement e) {
        byte[] b = e.compress().toByteArray();
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        String h = sb.toString();
        return h.length() > 40 ? h.substring(0, 20) + "…" + h.substring(h.length() - 20) : h;
    }

    private static String shortHex(RistrettoElement e) {
        byte[] b = e.compress().toByteArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(6, b.length); i++) sb.append(String.format("%02x", b[i]));
        return sb + "…";
    }
}
