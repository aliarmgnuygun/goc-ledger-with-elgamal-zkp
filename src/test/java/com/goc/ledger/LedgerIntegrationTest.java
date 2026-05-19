package com.goc.ledger;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.zkp.equivalence.CiphertextEquivalenceProof;
import com.goc.zkp.equivalence.CiphertextEquivalenceProver;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeWitness;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

class LedgerIntegrationTest {

    private Crypto crypto;
    private BitDecompositionRangeProver prover;
    private CiphertextEquivalenceProver equivalenceProver;
    private Ledger ledger;
    private BigInteger secretKey;
    private BigInteger publicKey;
    private CryptoGroup group;

    private final int BIT_LENGTH = 6; // 0..63

    // 2048-bit RFC 3526 Group 14 parameters — production grade,
    // guaranteed safe-prime structure (q is prime, g generates Q_p).
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
    private static final BigInteger Q_2048 =
            P_2048.subtract(BigInteger.ONE).divide(BigInteger.TWO);
    private static final BigInteger G_2048 = BigInteger.TWO;

    @BeforeEach
    void setUp() {
        BigInteger p = P_2048;
        BigInteger q = Q_2048;
        BigInteger g = G_2048;

        group  = new CryptoGroup(p, q, g);
        crypto = new Crypto(group);

        var keyPair = crypto.keyGen();
        secretKey = keyPair.secretKey;
        publicKey = keyPair.publicKey;

        prover            = new BitDecompositionRangeProver(group, crypto, BIT_LENGTH);
        equivalenceProver = new CiphertextEquivalenceProver(group, crypto);
        var verifier      = new BitDecompositionRangeVerifier(group, publicKey, BIT_LENGTH);

        ledger = new Ledger(group, 3, verifier);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Build a transaction bundle for sending {@code amount} from {@code sender}. */
    private Bundle buildTransfer(int sender, long amount) {
        Ciphertext currentBalance = ledger.computeBalance(sender);
        BigInteger balanceValue = decryptValue(currentBalance);
        long newBalanceValue = balanceValue.longValueExact() - amount;

        var amountWitness = new RangeWitness(BigInteger.valueOf(amount), secretKey, publicKey);
        var amountProof   = prover.prove(amountWitness);

        var newBalanceWitness = new RangeWitness(BigInteger.valueOf(newBalanceValue), secretKey, publicKey);
        var newBalanceProof   = prover.prove(newBalanceWitness);

        Ciphertext expectedNewBalance = subtract(currentBalance, amountProof.getEncryptedValue());
        var equivalence = equivalenceProver.prove(
                secretKey, publicKey,
                expectedNewBalance,
                newBalanceProof.getEncryptedValue()
        );

        return new Bundle(amountProof, newBalanceProof, equivalence);
    }

    private Ciphertext subtract(Ciphertext a, Ciphertext b) {
        return new Ciphertext(
                group.mul(a.c1, group.inverse(b.c1)),
                group.mul(a.c2, group.inverse(b.c2))
        );
    }

    private BigInteger decryptValue(Ciphertext ct) {
        BigInteger gm = crypto.decryptToGroupElement(ct, secretKey);
        long bound = (1L << BIT_LENGTH) * 8L;
        return crypto.babyStepGiantStepLog(gm, bound, group);
    }

    private record Bundle(RangeProof amountProof,
                          RangeProof newBalanceProof,
                          CiphertextEquivalenceProof equivalenceProof) {}

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    @Test
    void should_accept_transfer_when_sender_has_sufficient_balance() {
        ledger.mint(0, crypto.encrypt(BigInteger.valueOf(20), publicKey));

        Bundle b = buildTransfer(0, 5);

        boolean accepted = ledger.submitTransaction(
                0, 1,
                b.amountProof.getEncryptedValue(), b.amountProof,
                b.newBalanceProof.getEncryptedValue(), b.newBalanceProof,
                b.equivalenceProof, publicKey
        );

        assertThat(accepted).isTrue();
        assertThat(ledger.getEntry(0, 1)).isNotNull();
    }

    // -------------------------------------------------------------------------
    // Insufficient balance → rejected (negative new balance fails range proof)
    // -------------------------------------------------------------------------

    @Test
    void should_reject_transfer_when_sender_has_insufficient_balance() {
        ledger.mint(0, crypto.encrypt(BigInteger.valueOf(3), publicKey));

        // Try to send 10 while balance is only 3 — new balance would be −7.
        // The honest prover cannot even construct a valid range proof for −7,
        // so we simulate the malicious case: build the range proof for some
        // bogus non-negative value (e.g. 50) and try to splice it in.

        var amountWitness = new RangeWitness(BigInteger.valueOf(10), secretKey, publicKey);
        var amountProof   = prover.prove(amountWitness);

        // Forged "new balance" that the attacker pretends will be positive.
        var fakeNewBalanceWitness = new RangeWitness(BigInteger.valueOf(50), secretKey, publicKey);
        var fakeNewBalanceProof   = prover.prove(fakeNewBalanceWitness);

        // Attacker tries to provide an equivalence proof, but the math won't
        // line up: (current − amount) decrypts to −7, fakeNewBalance to 50.
        Ciphertext expectedNewBalance = subtract(
                ledger.computeBalance(0), amountProof.getEncryptedValue());
        var equivalence = equivalenceProver.prove(
                secretKey, publicKey,
                expectedNewBalance,
                fakeNewBalanceProof.getEncryptedValue()
        );

        boolean accepted = ledger.submitTransaction(
                0, 1,
                amountProof.getEncryptedValue(), amountProof,
                fakeNewBalanceProof.getEncryptedValue(), fakeNewBalanceProof,
                equivalence, publicKey
        );

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Equivalence proof tampering
    // -------------------------------------------------------------------------

    @Test
    void should_reject_when_equivalence_proof_is_tampered() {
        ledger.mint(0, crypto.encrypt(BigInteger.valueOf(20), publicKey));

        Bundle b = buildTransfer(0, 5);

        var tamperedEquivalence = new CiphertextEquivalenceProof(
                b.equivalenceProof.commitmentK1(),
                b.equivalenceProof.commitmentK2(),
                b.equivalenceProof.responseS().add(BigInteger.ONE)
        );

        boolean accepted = ledger.submitTransaction(
                0, 1,
                b.amountProof.getEncryptedValue(), b.amountProof,
                b.newBalanceProof.getEncryptedValue(), b.newBalanceProof,
                tamperedEquivalence, publicKey
        );

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Account with no funds at all → rejected
    // -------------------------------------------------------------------------

    @Test
    void should_reject_when_sender_has_no_funds() {
        // No mint for account 0.
        var amountWitness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var amountProof   = prover.prove(amountWitness);
        var newBalanceWitness = new RangeWitness(BigInteger.ZERO, secretKey, publicKey);
        var newBalanceProof   = prover.prove(newBalanceWitness);

        // Equivalence proof on null currentBalance is undefined; ledger should
        // reject before reaching it.
        boolean accepted = ledger.submitTransaction(
                0, 1,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof,
                new CiphertextEquivalenceProof(
                        BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO),
                publicKey
        );

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Homomorphic accumulation of inflows
    // -------------------------------------------------------------------------

    @Test
    void should_accumulate_inflows_into_recipient_balance() {
        ledger.mint(0, crypto.encrypt(BigInteger.valueOf(15), publicKey));
        ledger.mint(2, crypto.encrypt(BigInteger.valueOf(10), publicKey));

        Bundle b1 = buildTransfer(0, 3);
        ledger.submitTransaction(0, 1,
                b1.amountProof.getEncryptedValue(), b1.amountProof,
                b1.newBalanceProof.getEncryptedValue(), b1.newBalanceProof,
                b1.equivalenceProof, publicKey);

        Bundle b2 = buildTransfer(2, 4);
        ledger.submitTransaction(2, 1,
                b2.amountProof.getEncryptedValue(), b2.amountProof,
                b2.newBalanceProof.getEncryptedValue(), b2.newBalanceProof,
                b2.equivalenceProof, publicKey);

        // Recipient (account 1) accumulated 3 + 4 = 7.
        Ciphertext recipientBalance = ledger.computeBalance(1);
        BigInteger value = decryptValue(recipientBalance);

        assertThat(value).isEqualTo(BigInteger.valueOf(7));
    }
}
