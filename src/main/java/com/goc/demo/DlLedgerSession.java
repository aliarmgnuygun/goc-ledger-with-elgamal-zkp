package com.goc.demo;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.core.KeyPair;
import com.goc.crypto.Crypto;
import com.goc.zkp.equivalence.CiphertextEquivalenceProof;
import com.goc.zkp.equivalence.CiphertextEquivalenceProver;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeWitness;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeVerifier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Classic ElGamal (BigInteger, 2048-bit group) implementation of the
 * ledger demo session.
 */
public class DlLedgerSession implements LedgerService.Session {

    private static final String[] NAMES = {"Alice", "Bob", "Carol"};
    private static final long[]   MINTS = {20, 10, 5};
    private static final long     DECRYPT_BOUND = 1L << 16; // balances ≪ this

    private static final BigInteger P_2048 = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger Q_2048 = P_2048.subtract(BigInteger.ONE).divide(BigInteger.TWO);
    private static final BigInteger G_2048 = BigInteger.TWO;

    private final CryptoGroup group;
    private final Crypto crypto;
    private final BitDecompositionRangeProver prover;
    private final CiphertextEquivalenceProver equivalenceProver;
    private final com.goc.ledger.Ledger ledger;
    private final BigInteger sk;
    private final BigInteger pk;
    private final int bitLength;

    public DlLedgerSession(int bitLength) {
        this.bitLength = bitLength;
        this.group  = new CryptoGroup(P_2048, Q_2048, G_2048);
        this.crypto = new Crypto(group);

        KeyPair kp = crypto.keyGen();
        this.sk = kp.secretKey;
        this.pk = kp.publicKey;

        this.prover            = new BitDecompositionRangeProver(group, crypto, bitLength);
        this.equivalenceProver = new CiphertextEquivalenceProver(group, crypto);
        var verifier           = new BitDecompositionRangeVerifier(group, bitLength);

        this.ledger = new com.goc.ledger.Ledger(group, NAMES.length, verifier);
        for (int i = 0; i < NAMES.length; i++) {
            ledger.registerAccount(i, pk);
            ledger.mint(i, crypto.encrypt(BigInteger.valueOf(MINTS[i]), pk));
        }
    }

    @Override public String backend() { return "DL"; }
    @Override public int bitLength()  { return bitLength; }

    @Override
    public List<LedgerService.AccountView> accounts() {
        List<LedgerService.AccountView> out = new ArrayList<>();
        for (int i = 0; i < NAMES.length; i++) {
            Ciphertext bal = ledger.computeBalance(i);
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

        Ciphertext current = ledger.computeBalance(sender);
        long currentValue  = decrypt(current);
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
                                   long currentValue, Ciphertext current, List<String> log) {
        long newValue = currentValue - amount;
        if (newValue < 0) {
            log.add("Honest path: the new balance would be " + newValue + " < 0, so "
                    + NAMES[sender] + " is trying to send more than they have. A negative value "
                    + "has no valid range proof, so the transfer cannot be built. (Try the "
                    + "'Attack: fake new balance' mode to see how a lie is caught.)");
            return new TransferOutcome(false, log);
        }
        log.add("Step 2: " + NAMES[sender] + " sends " + amount + ", so the new balance will be " + newValue + ".");
        RangeProof amountProof     = prover.prove(new RangeWitness(BigInteger.valueOf(amount), sk, pk));
        RangeProof newBalanceProof = prover.prove(new RangeWitness(BigInteger.valueOf(newValue), sk, pk));
        log.add("Step 3: Range proofs are built for the amount (" + amount + " ≥ 0) and the new balance (" + newValue + " ≥ 0).");

        Ciphertext expected = subtract(current, amountProof.getEncryptedValue());
        CiphertextEquivalenceProof eq = equivalenceProver.prove(sk, pk, expected, newBalanceProof.getEncryptedValue());
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
                                      long currentValue, Ciphertext current, List<String> log) {
        long fake       = currentValue;             // lie: "my balance did not change"
        long honestNew  = currentValue - amount;    // what it should actually be
        log.add("Step 2: Cheat — here " + NAMES[sender] + " herself is dishonest. She sends " + amount
                + " to the receiver, but tells the ledger her own balance does NOT change (still "
                + fake + "), so she keeps her tokens. This would create money from nothing.");
        log.add("Step 3: She can even build a valid range proof for this false balance (" + fake + " ≥ 0).");

        RangeProof amountProof  = prover.prove(new RangeWitness(BigInteger.valueOf(amount), sk, pk));
        RangeProof fakeBalProof = prover.prove(new RangeWitness(BigInteger.valueOf(fake), sk, pk));

        Ciphertext expected = subtract(current, amountProof.getEncryptedValue());
        CiphertextEquivalenceProof eq = equivalenceProver.prove(sk, pk, expected, fakeBalProof.getEncryptedValue());
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
                                        Ciphertext current, List<String> log) {
        KeyPair attacker = crypto.keyGen();
        log.add("Step 2: Attack — an attacker (not " + NAMES[sender] + ") tries to send as "
                + NAMES[sender] + ", using their own key.");

        RangeProof amountProof     = prover.prove(new RangeWitness(BigInteger.valueOf(amount), attacker.secretKey, attacker.publicKey));
        RangeProof newBalanceProof = prover.prove(new RangeWitness(BigInteger.valueOf(amount), attacker.secretKey, attacker.publicKey));
        log.add("Step 3: All proofs are built with the attacker's key, not " + NAMES[sender] + "'s.");

        Ciphertext expected = subtract(current, amountProof.getEncryptedValue());
        CiphertextEquivalenceProof eq = equivalenceProver.prove(attacker.secretKey, attacker.publicKey,
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
                                   long currentValue, Ciphertext current, List<String> log) {
        long newValue = currentValue - amount;
        if (newValue < 0) {
            log.add("The tamper scenario needs enough balance (new balance ≥ 0). Try a smaller amount.");
            return new TransferOutcome(false, log);
        }
        log.add("Step 2: A real, valid transfer of " + amount + " is built (new balance " + newValue + ") — every proof is correct and the key is " + NAMES[sender] + "'s own.");
        RangeProof amountProof     = prover.prove(new RangeWitness(BigInteger.valueOf(amount), sk, pk));
        RangeProof newBalanceProof = prover.prove(new RangeWitness(BigInteger.valueOf(newValue), sk, pk));
        Ciphertext expected = subtract(current, amountProof.getEncryptedValue());
        CiphertextEquivalenceProof eq = equivalenceProver.prove(sk, pk, expected, newBalanceProof.getEncryptedValue());

        log.add("Step 3: Tamper — after the proof is built, one number inside it (the equivalence response s) is changed by +1. Only the proof is edited; the key is still correct.");
        CiphertextEquivalenceProof tampered = new CiphertextEquivalenceProof(
                eq.commitmentK1(), eq.commitmentK2(), eq.responseS().add(BigInteger.ONE).mod(group.q));

        boolean accepted = ledger.submitTransaction(sender, receiver,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof, tampered);
        log.add(accepted
                ? "Result: ACCEPT — unexpected!"
                : "Result: REJECT ✗ — the verifier recomputes the Fiat–Shamir challenge and sees the proof no longer fits. Even a 1-number change breaks it.");
        return new TransferOutcome(accepted, log);
    }

    // -------------------------------------------------------------- helpers

    private Ciphertext subtract(Ciphertext a, Ciphertext b) {
        return new Ciphertext(
                group.mul(a.c1, group.inverse(b.c1)),
                group.mul(a.c2, group.inverse(b.c2)));
    }

    private long decrypt(Ciphertext ct) {
        if (ct == null) return 0;
        BigInteger gm = crypto.decryptToGroupElement(ct, sk);
        // Demo balances are tiny (conserved sum of mints); cap the discrete-log
        // search independently of bitLength so 32-bit proofs stay snappy.
        return crypto.babyStepGiantStepLog(gm, DECRYPT_BOUND, group).longValueExact();
    }

    private static String hex(BigInteger v) {
        byte[] b = v.toByteArray();
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        String h = sb.toString();
        return h.length() > 40 ? h.substring(0, 20) + "…" + h.substring(h.length() - 20) : h;
    }

    private static String shortHex(BigInteger v) {
        String h = v.toString(16);
        return h.length() > 12 ? h.substring(0, 12) + "…" : h;
    }
}
