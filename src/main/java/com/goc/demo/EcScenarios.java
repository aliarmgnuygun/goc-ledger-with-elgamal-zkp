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
import java.util.List;

/**
 * Re-runs each {@code ECLedgerIntegrationTest} scenario on a fresh,
 * self-contained ledger so the web demo mirrors the JUnit suite 1:1.
 * Each method returns whether the ledger ACCEPTED the transaction and
 * appends a human-readable trace to {@code log}.
 */
public class EcScenarios {

    private static final int BIT_LENGTH = 32;
    // Demo balances are tiny; cap the discrete-log search independently of
    // BIT_LENGTH so decryption stays fast even with a 32-bit range.
    private static final long DECRYPT_BOUND = 1L << 16;
    private static final String[] NAMES = {"Alice", "Bob", "Carol"};

    /** Builds a fresh, registered, three-account context for a scenario. */
    private static final class Ctx {
        final ECCryptoGroup group = new ECCryptoGroup();
        final ECCrypto crypto = new ECCrypto(group);
        final ECKeyPair kp = crypto.keyGen();
        final ECBitDecompositionRangeProver prover =
                new ECBitDecompositionRangeProver(group, crypto, BIT_LENGTH);
        final ECCiphertextEquivalenceProver eq =
                new ECCiphertextEquivalenceProver(group, crypto);
        final ECLedger ledger =
                new ECLedger(group, 3, new ECBitDecompositionRangeVerifier(group, BIT_LENGTH));

        Ctx(boolean registerAll) {
            if (registerAll) {
                for (int i = 0; i < 3; i++) ledger.registerAccount(i, kp.publicKey);
            }
        }

        ECRangeProof prove(long v) {
            return prover.prove(new ECRangeWitness(BigInteger.valueOf(v), kp.secretKey, kp.publicKey));
        }

        long decrypt(ECCiphertext ct) {
            RistrettoElement gm = crypto.decryptToGroupElement(ct, kp.secretKey);
            return crypto.babyStepGiantStepLog(gm, DECRYPT_BOUND);
        }
    }

    public boolean run(String id, List<String> log) {
        return switch (id) {
            case "SUFFICIENT"   -> sufficient(log);
            case "INSUFFICIENT" -> insufficient(log);
            case "TAMPER"       -> tamper(log);
            case "IMPERSONATE"  -> impersonate(log);
            case "NO_FUNDS"     -> noFunds(log);
            case "UNREGISTERED" -> unregistered(log);
            case "ACCUMULATE"   -> accumulate(log);
            case "REPLAY"       -> replay(log);
            case "DOUBLE_SPEND" -> doubleSpend(log);
            case "AMOUNT_SPLICE"-> amountSplice(log);
            default -> { log.add("Unknown scenario: " + id); yield false; }
        };
    }

    private boolean sufficient(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(20, c.kp.publicKey));
        log.add("Step 1: Alice is given 20 tokens (stored encrypted).");
        log.add("Step 2: Alice sends 5 to Bob, so her new balance will be 15.");
        ECRangeProof amt = c.prove(5);
        ECRangeProof bal = c.prove(15);
        log.add("Step 3: She builds range proofs for the amount (5 ≥ 0) and the new balance (15 ≥ 0).");
        ECCiphertext expected = c.ledger.computeBalance(0).subtract(amt.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        log.add("Step 4: She builds an equivalence proof: new balance == current − amount (without showing the numbers).");
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, eq);
        log.add(ok ? "Result: ACCEPT ✓ — all proofs are valid, so the ledger applies the transfer."
                   : "Result: REJECT ✗ — unexpected.");
        return ok;
    }

    private boolean insufficient(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(3, c.kp.publicKey));
        log.add("Step 1: Alice is given only 3 tokens.");
        log.add("Step 2: Alice tries to send 10, but she has only 3 — this is overspending.");
        log.add("Step 3: Her real new balance would be 3 − 10 = −7 (negative, no valid range proof), so she lies and claims it is 50 and builds a valid range proof for 50.");
        ECRangeProof amt = c.prove(10);
        ECRangeProof fake = c.prove(50);
        ECCiphertext expected = c.ledger.computeBalance(0).subtract(amt.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, fake.getEncryptedValue());
        log.add("Step 4: The ledger checks the equivalence proof: the new balance must equal current − amount = 3 − 10 = −7, not 50.");
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                fake.getEncryptedValue(), fake, eq);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the equivalence proof fails; the lie is caught and overspending is blocked.");
        return ok;
    }

    private boolean tamper(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(20, c.kp.publicKey));
        log.add("Step 1: Alice is given 20 tokens.");
        ECRangeProof amt = c.prove(5);
        ECRangeProof bal = c.prove(15);
        ECCiphertext expected = c.ledger.computeBalance(0).subtract(amt.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        log.add("Step 2: A real, valid transfer of 5 is built (new balance 15) — every proof is correct.");
        log.add("Step 3: Tamper — after the proof is built, one number inside it (the equivalence response s) is changed by +1.");
        ECCiphertextEquivalenceProof tampered = new ECCiphertextEquivalenceProof(
                eq.commitmentK1(), eq.commitmentK2(), eq.responseS().add(Scalar.ONE));
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, tampered);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the verifier recomputes the Fiat–Shamir challenge and catches the change.");
        return ok;
    }

    private boolean impersonate(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(20, c.kp.publicKey));
        ECKeyPair attacker = c.crypto.keyGen();
        log.add("Step 1: Alice (account 0) is given 20 tokens.");
        log.add("Step 2: Attack — the attacker uses their OWN key to build the proofs, but sends as Alice (account 0).");
        ECRangeProof amt = c.prover.prove(new ECRangeWitness(BigInteger.valueOf(5), attacker.secretKey, attacker.publicKey));
        ECRangeProof bal = c.prover.prove(new ECRangeWitness(BigInteger.valueOf(15), attacker.secretKey, attacker.publicKey));
        ECCiphertext expected = c.ledger.computeBalance(0).subtract(amt.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = c.eq.prove(attacker.secretKey, attacker.publicKey, expected, bal.getEncryptedValue());
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, eq);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the proofs do not verify against Alice's registered key (binding proof).");
        return ok;
    }

    private boolean noFunds(List<String> log) {
        Ctx c = new Ctx(true);
        log.add("Step 1: Account 0 has no tokens (it was never minted).");
        log.add("Step 2: It still tries to send 5.");
        ECRangeProof amt = c.prove(5);
        ECRangeProof bal = c.prove(0);
        ECCiphertextEquivalenceProof dummy = new ECCiphertextEquivalenceProof(c.group.g, c.group.g, Scalar.ONE);
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, dummy);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the sender has no balance at all.");
        return ok;
    }

    private boolean unregistered(List<String> log) {
        Ctx c = new Ctx(false); // no account is registered
        c.ledger.mint(0, c.crypto.encrypt(20, c.kp.publicKey));
        log.add("Step 1: Account 0 has tokens, but its public key is NOT registered on the ledger.");
        log.add("Step 2: It tries to send 5.");
        ECRangeProof amt = c.prove(5);
        ECRangeProof bal = c.prove(15);
        ECCiphertextEquivalenceProof dummy = new ECCiphertextEquivalenceProof(c.group.g, c.group.g, Scalar.ONE);
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, dummy);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — an unregistered account cannot send.");
        return ok;
    }

    private boolean accumulate(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(15, c.kp.publicKey));
        c.ledger.mint(2, c.crypto.encrypt(10, c.kp.publicKey));
        log.add("Step 1: Alice has 15 and Carol has 10. Bob (account 1) starts with 0.");
        log.add("Step 2: Alice sends 3 to Bob.");
        transferTo(c, 0, 1, 3, log);
        log.add("Step 3: Carol sends 4 to Bob.");
        transferTo(c, 2, 1, 4, log);
        long bobBalance = c.decrypt(c.ledger.computeBalance(1));
        log.add("Step 4: Bob's balance is the homomorphic sum of his incoming transfers: " + bobBalance + " (expected 3 + 4 = 7).");
        boolean ok = (bobBalance == 7);
        log.add(ok ? "Result: ACCEPT ✓ — the incoming transfers add up correctly."
                   : "Result: REJECT ✗ — wrong sum.");
        return ok;
    }

    private boolean replay(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(20, c.kp.publicKey));
        log.add("Step 1: Alice has 20. A valid transfer of 5 to Bob is built (new balance 15).");
        ECRangeProof amt = c.prove(5);
        ECRangeProof bal = c.prove(15);
        ECCiphertext expected = c.ledger.computeBalance(0).subtract(amt.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        boolean first = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt, bal.getEncryptedValue(), bal, eq);
        log.add("Step 2: The transfer is submitted and " + (first ? "ACCEPTED ✓" : "rejected")
                + ". Alice's balance is now " + c.decrypt(c.ledger.computeBalance(0)) + ".");
        log.add("Step 3: Replay — the SAME proofs are submitted a second time.");
        boolean second = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt, bal.getEncryptedValue(), bal, eq);
        log.add("Step 4: The ledger recomputes current − amount = 15 − 5 = 10, which no longer matches the replayed new balance (15).");
        log.add(second ? "Result: ACCEPT — unexpected!"
                       : "Result: REJECT ✗ — the proof was tied to the old balance (20); once the balance changes, the replay fails.");
        return second;
    }

    private boolean doubleSpend(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(20, c.kp.publicKey));
        log.add("Step 1: Alice has 20. She prepares TWO transfers of 15 at the same time, both based on her current balance 20 (this models concurrency).");
        ECCiphertext bal20 = c.ledger.computeBalance(0);
        ECRangeProof amt1 = c.prove(15); ECRangeProof new1 = c.prove(5);
        ECCiphertextEquivalenceProof eq1 = c.eq.prove(c.kp.secretKey, c.kp.publicKey,
                bal20.subtract(amt1.getEncryptedValue()), new1.getEncryptedValue());
        ECRangeProof amt2 = c.prove(15); ECRangeProof new2 = c.prove(5);
        ECCiphertextEquivalenceProof eq2 = c.eq.prove(c.kp.secretKey, c.kp.publicKey,
                bal20.subtract(amt2.getEncryptedValue()), new2.getEncryptedValue());
        log.add("Step 2: The first transfer (Alice → Bob, 15) is submitted.");
        boolean first = c.ledger.submitTransaction(0, 1, amt1.getEncryptedValue(), amt1, new1.getEncryptedValue(), new1, eq1);
        log.add("        " + (first ? "ACCEPT ✓ — Alice's balance is now " + c.decrypt(c.ledger.computeBalance(0)) + "." : "rejected."));
        log.add("Step 3: The second transfer (Alice → Carol, 15) is submitted, but it was built against the old balance 20.");
        boolean second = c.ledger.submitTransaction(0, 2, amt2.getEncryptedValue(), amt2, new2.getEncryptedValue(), new2, eq2);
        log.add("Step 4: The ledger now computes current − amount = 5 − 15 = −10, which does not match the claimed new balance (5).");
        log.add(second ? "Result: ACCEPT — unexpected!"
                       : "Result: REJECT ✗ — only one of the two double-spends can succeed.");
        return second;
    }

    private boolean amountSplice(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(20, c.kp.publicKey));
        log.add("Step 1: Alice has 20. A valid range proof is built for amount = 5.");
        ECRangeProof amt = c.prove(5);
        ECRangeProof bal = c.prove(15);
        log.add("Step 2: Splice — Alice submits the proof for 5, but passes a DIFFERENT ciphertext (an encryption of 7) as the actual amount.");
        ECCiphertext fakeAmount = c.crypto.encrypt(7, c.kp.publicKey);
        ECCiphertext expected = c.ledger.computeBalance(0).subtract(amt.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        log.add("Step 3: The ledger checks that the submitted amount equals the amount inside the proof: Enc(7) == Enc(5)? No.");
        boolean ok = c.ledger.submitTransaction(0, 1, fakeAmount, amt, bal.getEncryptedValue(), bal, eq);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the stored amount must match the amount proven by the range proof.");
        return ok;
    }

    private void transferTo(Ctx c, int sender, int receiver, long amount, List<String> log) {
        long current = c.decrypt(c.ledger.computeBalance(sender));
        ECRangeProof amt = c.prove(amount);
        ECRangeProof bal = c.prove(current - amount);
        ECCiphertext expected = c.ledger.computeBalance(sender).subtract(amt.getEncryptedValue());
        ECCiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        boolean ok = c.ledger.submitTransaction(sender, receiver, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, eq);
        log.add("        " + NAMES[sender] + " → " + NAMES[receiver] + " (" + amount + "): " + (ok ? "ACCEPT ✓" : "REJECT ✗"));
    }
}
