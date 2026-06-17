package com.goc.demo;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.core.KeyPair;
import com.goc.crypto.Crypto;
import com.goc.ledger.Ledger;
import com.goc.zkp.equivalence.CiphertextEquivalenceProof;
import com.goc.zkp.equivalence.CiphertextEquivalenceProver;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeWitness;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeVerifier;

import java.math.BigInteger;
import java.util.List;

/**
 * Re-runs each {@code LedgerIntegrationTest} (classic ElGamal) scenario on a
 * fresh, self-contained ledger so the web demo mirrors the JUnit suite 1:1.
 */
public class DlScenarios {

    private static final int BIT_LENGTH = 8;
    private static final String[] NAMES = {"Alice", "Bob", "Carol"};

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

    private static final class Ctx {
        final CryptoGroup group = new CryptoGroup(P_2048, Q_2048, G_2048);
        final Crypto crypto = new Crypto(group);
        final KeyPair kp = crypto.keyGen();
        final BitDecompositionRangeProver prover =
                new BitDecompositionRangeProver(group, crypto, BIT_LENGTH);
        final CiphertextEquivalenceProver eq =
                new CiphertextEquivalenceProver(group, crypto);
        final Ledger ledger =
                new Ledger(group, 3, new BitDecompositionRangeVerifier(group, BIT_LENGTH));

        Ctx(boolean registerAll) {
            if (registerAll) {
                for (int i = 0; i < 3; i++) ledger.registerAccount(i, kp.publicKey);
            }
        }

        RangeProof prove(long v) {
            return prover.prove(new RangeWitness(BigInteger.valueOf(v), kp.secretKey, kp.publicKey));
        }

        Ciphertext subtract(Ciphertext a, Ciphertext b) {
            return new Ciphertext(group.mul(a.c1, group.inverse(b.c1)),
                                  group.mul(a.c2, group.inverse(b.c2)));
        }

        long decrypt(Ciphertext ct) {
            BigInteger gm = crypto.decryptToGroupElement(ct, kp.secretKey);
            return crypto.babyStepGiantStepLog(gm, (1L << BIT_LENGTH) * 8L, group).longValueExact();
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
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(20), c.kp.publicKey));
        log.add("Step 1: Alice is given 20 tokens (stored encrypted).");
        log.add("Step 2: Alice sends 5 to Bob, so her new balance will be 15.");
        RangeProof amt = c.prove(5);
        RangeProof bal = c.prove(15);
        log.add("Step 3: She builds range proofs for the amount (5 ≥ 0) and the new balance (15 ≥ 0).");
        Ciphertext expected = c.subtract(c.ledger.computeBalance(0), amt.getEncryptedValue());
        CiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        log.add("Step 4: She builds an equivalence proof: new balance == current − amount (without showing the numbers).");
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, eq);
        log.add(ok ? "Result: ACCEPT ✓ — all proofs are valid, so the ledger applies the transfer."
                   : "Result: REJECT ✗ — unexpected.");
        return ok;
    }

    private boolean insufficient(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(3), c.kp.publicKey));
        log.add("Step 1: Alice is given only 3 tokens.");
        log.add("Step 2: Alice tries to send 10, but she has only 3 — this is overspending.");
        log.add("Step 3: Her real new balance would be 3 − 10 = −7 (negative, no valid range proof), so she lies and claims it is 50 and builds a valid range proof for 50.");
        RangeProof amt = c.prove(10);
        RangeProof fake = c.prove(50);
        Ciphertext expected = c.subtract(c.ledger.computeBalance(0), amt.getEncryptedValue());
        CiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, fake.getEncryptedValue());
        log.add("Step 4: The ledger checks the equivalence proof: the new balance must equal current − amount = 3 − 10 = −7, not 50.");
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                fake.getEncryptedValue(), fake, eq);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the equivalence proof fails; the lie is caught and overspending is blocked.");
        return ok;
    }

    private boolean tamper(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(20), c.kp.publicKey));
        log.add("Step 1: Alice is given 20 tokens.");
        RangeProof amt = c.prove(5);
        RangeProof bal = c.prove(15);
        Ciphertext expected = c.subtract(c.ledger.computeBalance(0), amt.getEncryptedValue());
        CiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        log.add("Step 2: A real, valid transfer of 5 is built (new balance 15) — every proof is correct.");
        log.add("Step 3: Tamper — after the proof is built, one number inside it (the equivalence response s) is changed by +1.");
        CiphertextEquivalenceProof tampered = new CiphertextEquivalenceProof(
                eq.commitmentK1(), eq.commitmentK2(), eq.responseS().add(BigInteger.ONE).mod(c.group.q));
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, tampered);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the verifier recomputes the Fiat–Shamir challenge and catches the change.");
        return ok;
    }

    private boolean impersonate(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(20), c.kp.publicKey));
        KeyPair attacker = c.crypto.keyGen();
        log.add("Step 1: Alice (account 0) is given 20 tokens.");
        log.add("Step 2: Attack — the attacker uses their OWN key to build the proofs, but sends as Alice (account 0).");
        RangeProof amt = c.prover.prove(new RangeWitness(BigInteger.valueOf(5), attacker.secretKey, attacker.publicKey));
        RangeProof bal = c.prover.prove(new RangeWitness(BigInteger.valueOf(15), attacker.secretKey, attacker.publicKey));
        Ciphertext expected = c.subtract(c.ledger.computeBalance(0), amt.getEncryptedValue());
        CiphertextEquivalenceProof eq = c.eq.prove(attacker.secretKey, attacker.publicKey, expected, bal.getEncryptedValue());
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
        RangeProof amt = c.prove(5);
        RangeProof bal = c.prove(0);
        CiphertextEquivalenceProof dummy = new CiphertextEquivalenceProof(BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO);
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, dummy);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the sender has no balance at all.");
        return ok;
    }

    private boolean unregistered(List<String> log) {
        Ctx c = new Ctx(false); // no account is registered
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(20), c.kp.publicKey));
        log.add("Step 1: Account 0 has tokens, but its public key is NOT registered on the ledger.");
        log.add("Step 2: It tries to send 5.");
        RangeProof amt = c.prove(5);
        RangeProof bal = c.prove(15);
        CiphertextEquivalenceProof dummy = new CiphertextEquivalenceProof(BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO);
        boolean ok = c.ledger.submitTransaction(0, 1, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, dummy);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — an unregistered account cannot send.");
        return ok;
    }

    private boolean accumulate(List<String> log) {
        Ctx c = new Ctx(true);
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(15), c.kp.publicKey));
        c.ledger.mint(2, c.crypto.encrypt(BigInteger.valueOf(10), c.kp.publicKey));
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
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(20), c.kp.publicKey));
        log.add("Step 1: Alice has 20. A valid transfer of 5 to Bob is built (new balance 15).");
        RangeProof amt = c.prove(5);
        RangeProof bal = c.prove(15);
        Ciphertext expected = c.subtract(c.ledger.computeBalance(0), amt.getEncryptedValue());
        CiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
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
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(20), c.kp.publicKey));
        log.add("Step 1: Alice has 20. She prepares TWO transfers of 15 at the same time, both based on her current balance 20 (this models concurrency).");
        Ciphertext bal20 = c.ledger.computeBalance(0);
        RangeProof amt1 = c.prove(15); RangeProof new1 = c.prove(5);
        CiphertextEquivalenceProof eq1 = c.eq.prove(c.kp.secretKey, c.kp.publicKey,
                c.subtract(bal20, amt1.getEncryptedValue()), new1.getEncryptedValue());
        RangeProof amt2 = c.prove(15); RangeProof new2 = c.prove(5);
        CiphertextEquivalenceProof eq2 = c.eq.prove(c.kp.secretKey, c.kp.publicKey,
                c.subtract(bal20, amt2.getEncryptedValue()), new2.getEncryptedValue());
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
        c.ledger.mint(0, c.crypto.encrypt(BigInteger.valueOf(20), c.kp.publicKey));
        log.add("Step 1: Alice has 20. A valid range proof is built for amount = 5.");
        RangeProof amt = c.prove(5);
        RangeProof bal = c.prove(15);
        log.add("Step 2: Splice — Alice submits the proof for 5, but passes a DIFFERENT ciphertext (an encryption of 7) as the actual amount.");
        Ciphertext fakeAmount = c.crypto.encrypt(BigInteger.valueOf(7), c.kp.publicKey);
        Ciphertext expected = c.subtract(c.ledger.computeBalance(0), amt.getEncryptedValue());
        CiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        log.add("Step 3: The ledger checks that the submitted amount equals the amount inside the proof: Enc(7) == Enc(5)? No.");
        boolean ok = c.ledger.submitTransaction(0, 1, fakeAmount, amt, bal.getEncryptedValue(), bal, eq);
        log.add(ok ? "Result: ACCEPT — unexpected!"
                   : "Result: REJECT ✗ — the stored amount must match the amount proven by the range proof.");
        return ok;
    }

    private void transferTo(Ctx c, int sender, int receiver, long amount, List<String> log) {
        long current = c.decrypt(c.ledger.computeBalance(sender));
        RangeProof amt = c.prove(amount);
        RangeProof bal = c.prove(current - amount);
        Ciphertext expected = c.subtract(c.ledger.computeBalance(sender), amt.getEncryptedValue());
        CiphertextEquivalenceProof eq = c.eq.prove(c.kp.secretKey, c.kp.publicKey, expected, bal.getEncryptedValue());
        boolean ok = c.ledger.submitTransaction(sender, receiver, amt.getEncryptedValue(), amt,
                bal.getEncryptedValue(), bal, eq);
        log.add("        " + NAMES[sender] + " → " + NAMES[receiver] + " (" + amount + "): " + (ok ? "ACCEPT ✓" : "REJECT ✗"));
    }
}
