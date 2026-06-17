package com.goc.ledger.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.goc.crypto.ec.ECCrypto;
import com.goc.zkp.equivalence.ec.ECCiphertextEquivalenceProof;
import com.goc.zkp.equivalence.ec.ECCiphertextEquivalenceProver;
import com.goc.zkp.range.bitdecomposition.ec.ECBitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.ec.ECBitDecompositionRangeVerifier;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeWitness;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

class ECLedgerIntegrationTest {

    private ECCryptoGroup                 group;
    private ECCrypto                      crypto;
    private ECBitDecompositionRangeProver prover;
    private ECCiphertextEquivalenceProver equivalenceProver;
    private ECLedger                      ledger;
    private Scalar                        secretKey;
    private RistrettoElement              publicKey;

    private final int BIT_LENGTH = 6; // 0..63

    @BeforeEach
    void setUp() {
        group  = new ECCryptoGroup();
        crypto = new ECCrypto(group);

        ECKeyPair keyPair = crypto.keyGen();
        secretKey = keyPair.secretKey;
        publicKey = keyPair.publicKey;

        prover            = new ECBitDecompositionRangeProver(group, crypto, BIT_LENGTH);
        equivalenceProver = new ECCiphertextEquivalenceProver(group, crypto);
        var verifier      = new ECBitDecompositionRangeVerifier(group, BIT_LENGTH);

        ledger = new ECLedger(group, 3, verifier);
        ledger.registerAccount(0, publicKey);
        ledger.registerAccount(1, publicKey);
        ledger.registerAccount(2, publicKey);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private record Bundle(ECRangeProof                 amountProof,
                          ECRangeProof                 newBalanceProof,
                          ECCiphertextEquivalenceProof equivalenceProof) {}

    private Bundle buildTransfer(int sender, long amount) {
        ECCiphertext current      = ledger.computeBalance(sender);
        long         currentValue = decryptValue(current);
        long         newValue     = currentValue - amount;

        var amountWitness = new ECRangeWitness(BigInteger.valueOf(amount), secretKey, publicKey);
        var amountProof   = prover.prove(amountWitness);

        var newBalanceWitness = new ECRangeWitness(BigInteger.valueOf(newValue), secretKey, publicKey);
        var newBalanceProof   = prover.prove(newBalanceWitness);

        ECCiphertext expectedNewBalance = current.subtract(amountProof.getEncryptedValue());
        var equivalence = equivalenceProver.prove(
                secretKey, publicKey,
                expectedNewBalance,
                newBalanceProof.getEncryptedValue()
        );

        return new Bundle(amountProof, newBalanceProof, equivalence);
    }

    private long decryptValue(ECCiphertext ct) {
        RistrettoElement gm = crypto.decryptToGroupElement(ct, secretKey);
        long bound = (1L << BIT_LENGTH) * 8L;
        return crypto.babyStepGiantStepLog(gm, bound);
    }

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    @Test
    void should_accept_transfer_when_sender_has_sufficient_balance() {
        ledger.mint(0, crypto.encrypt(20L, publicKey));

        Bundle b = buildTransfer(0, 5L);

        boolean accepted = ledger.submitTransaction(
                0, 1,
                b.amountProof.getEncryptedValue(), b.amountProof,
                b.newBalanceProof.getEncryptedValue(), b.newBalanceProof,
                b.equivalenceProof
        );

        assertThat(accepted).isTrue();
        assertThat(ledger.getEntry(0, 1)).isNotNull();
    }

    // -------------------------------------------------------------------------
    // Insufficient balance — equivalence proof catches the lie
    // -------------------------------------------------------------------------

    @Test
    void should_reject_transfer_when_sender_has_insufficient_balance() {
        ledger.mint(0, crypto.encrypt(3L, publicKey));

        // Try to send 10 while balance is only 3 — real new balance would be −7.
        // The attacker fakes a "newBalance = 50" with a valid range proof.
        var amountWitness     = new ECRangeWitness(BigInteger.valueOf(10), secretKey, publicKey);
        var amountProof       = prover.prove(amountWitness);
        var fakeNewBalance    = new ECRangeWitness(BigInteger.valueOf(50), secretKey, publicKey);
        var fakeNewBalanceProof = prover.prove(fakeNewBalance);

        ECCiphertext expectedNewBalance = ledger.computeBalance(0)
                .subtract(amountProof.getEncryptedValue());
        var equivalence = equivalenceProver.prove(
                secretKey, publicKey,
                expectedNewBalance,
                fakeNewBalanceProof.getEncryptedValue()
        );

        boolean accepted = ledger.submitTransaction(
                0, 1,
                amountProof.getEncryptedValue(), amountProof,
                fakeNewBalanceProof.getEncryptedValue(), fakeNewBalanceProof,
                equivalence
        );

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Equivalence proof tampering
    // -------------------------------------------------------------------------

    @Test
    void should_reject_when_equivalence_proof_is_tampered() {
        ledger.mint(0, crypto.encrypt(20L, publicKey));

        Bundle b = buildTransfer(0, 5L);

        var tamperedEquivalence = new ECCiphertextEquivalenceProof(
                b.equivalenceProof.commitmentK1(),
                b.equivalenceProof.commitmentK2(),
                b.equivalenceProof.responseS().add(Scalar.ONE)
        );

        boolean accepted = ledger.submitTransaction(
                0, 1,
                b.amountProof.getEncryptedValue(), b.amountProof,
                b.newBalanceProof.getEncryptedValue(), b.newBalanceProof,
                tamperedEquivalence
        );

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Account with no funds at all → rejected
    // -------------------------------------------------------------------------

    @Test
    void should_reject_when_sender_has_no_funds() {
        // No mint for account 0.
        var amountWitness     = new ECRangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var amountProof       = prover.prove(amountWitness);
        var newBalanceWitness = new ECRangeWitness(BigInteger.ZERO, secretKey, publicKey);
        var newBalanceProof   = prover.prove(newBalanceWitness);

        boolean accepted = ledger.submitTransaction(
                0, 1,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof,
                new ECCiphertextEquivalenceProof(
                        group.g, group.g, Scalar.ONE)
        );

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Homomorphic accumulation of inflows
    // -------------------------------------------------------------------------

    @Test
    void should_accumulate_inflows_into_recipient_balance() {
        ledger.mint(0, crypto.encrypt(15L, publicKey));
        ledger.mint(2, crypto.encrypt(10L, publicKey));

        Bundle b1 = buildTransfer(0, 3L);
        ledger.submitTransaction(0, 1,
                b1.amountProof.getEncryptedValue(), b1.amountProof,
                b1.newBalanceProof.getEncryptedValue(), b1.newBalanceProof,
                b1.equivalenceProof);

        Bundle b2 = buildTransfer(2, 4L);
        ledger.submitTransaction(2, 1,
                b2.amountProof.getEncryptedValue(), b2.amountProof,
                b2.newBalanceProof.getEncryptedValue(), b2.newBalanceProof,
                b2.equivalenceProof);

        // Recipient (account 1) accumulated 3 + 4 = 7.
        ECCiphertext recipientBalance = ledger.computeBalance(1);
        long value = decryptValue(recipientBalance);

        assertThat(value).isEqualTo(7L);
    }

    // -------------------------------------------------------------------------
    // Sender authentication: another user cannot submit as Alice
    // -------------------------------------------------------------------------

    @Test
    void should_reject_when_attacker_impersonates_another_account() {
        ledger.mint(0, crypto.encrypt(20L, publicKey));

        ECKeyPair attacker = crypto.keyGen();

        // Attacker builds proofs with HIS OWN secret key but claims sender=0.
        ECCiphertext currentBalance = ledger.computeBalance(0);

        var amountWitness     = new ECRangeWitness(BigInteger.valueOf(5),
                attacker.secretKey, attacker.publicKey);
        var amountProof       = prover.prove(amountWitness);
        var newBalanceWitness = new ECRangeWitness(BigInteger.valueOf(15),
                attacker.secretKey, attacker.publicKey);
        var newBalanceProof   = prover.prove(newBalanceWitness);

        ECCiphertext expectedNewBalance = currentBalance.subtract(amountProof.getEncryptedValue());
        var equivalence = equivalenceProver.prove(
                attacker.secretKey, attacker.publicKey,
                expectedNewBalance,
                newBalanceProof.getEncryptedValue()
        );

        boolean accepted = ledger.submitTransaction(
                0, 1,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof,
                equivalence
        );

        assertThat(accepted).isFalse();
    }

    @Test
    void should_reject_when_sender_account_is_not_registered() {
        var freshVerifier = new ECBitDecompositionRangeVerifier(group, BIT_LENGTH);
        var freshLedger   = new ECLedger(group, 3, freshVerifier);
        freshLedger.mint(0, crypto.encrypt(20L, publicKey));

        var amountWitness     = new ECRangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var amountProof       = prover.prove(amountWitness);
        var newBalanceWitness = new ECRangeWitness(BigInteger.valueOf(15), secretKey, publicKey);
        var newBalanceProof   = prover.prove(newBalanceWitness);

        boolean accepted = freshLedger.submitTransaction(
                0, 1,
                amountProof.getEncryptedValue(), amountProof,
                newBalanceProof.getEncryptedValue(), newBalanceProof,
                new ECCiphertextEquivalenceProof(group.g, group.g, Scalar.ONE)
        );

        assertThat(accepted).isFalse();
    }
}
