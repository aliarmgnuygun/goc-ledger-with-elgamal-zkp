package com.goc.ledger;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
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
    private Ledger ledger;
    private BigInteger secretKey;
    private BigInteger publicKey;
    private CryptoGroup group;

    private final int BIT_LENGTH = 4;

    @BeforeEach
    void setUp() {
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        group = new CryptoGroup(p, q, g);
        crypto = new Crypto(group);

        var keyPair = crypto.keyGen();
        secretKey = keyPair.secretKey;
        publicKey = keyPair.publicKey;

        prover = new BitDecompositionRangeProver(group, crypto, BIT_LENGTH);
        var verifier = new BitDecompositionRangeVerifier(group, publicKey, BIT_LENGTH);

        ledger = new Ledger(group, 3, verifier);
    }

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    @Test
    void should_accept_valid_transaction_and_store_ciphertext() {
        var witness = new RangeWitness(BigInteger.valueOf(5), publicKey);
        var proof   = prover.prove(witness);

        boolean accepted = ledger.submitTransaction(0, 1, proof.getEncryptedValue(), proof);

        assertThat(accepted).isTrue();
        assertThat(ledger.getEntry(0, 1)).isNotNull();
    }

    // -------------------------------------------------------------------------
    // Binding attack
    // -------------------------------------------------------------------------

    @Test
    void should_reject_transaction_when_ciphertext_does_not_match_proof() {
        var witness = new RangeWitness(BigInteger.valueOf(5), publicKey);
        var proof   = prover.prove(witness);

        Ciphertext fake = crypto.encrypt(BigInteger.valueOf(10), publicKey);

        boolean accepted = ledger.submitTransaction(0, 1, fake, proof);

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Proof tampering
    // -------------------------------------------------------------------------

    @Test
    void should_reject_when_proof_is_tampered() {
        var witness = new RangeWitness(BigInteger.valueOf(6), publicKey);
        var proof   = prover.prove(witness);

        RangeProof tampered = new RangeProof(
                proof.getBitCommitments(),
                proof.getBitProofs(),
                new Ciphertext(
                        proof.getEncryptedValue().c1,
                        proof.getEncryptedValue().c2.add(BigInteger.ONE)
                ),
                proof.getBitLength()
        );

        boolean accepted = ledger.submitTransaction(0, 1, tampered.getEncryptedValue(), tampered);

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Replay attack
    // -------------------------------------------------------------------------

    @Test
    void should_reject_replay_attack_using_same_proof_with_different_ciphertext() {
        var witness = new RangeWitness(BigInteger.valueOf(4), publicKey);
        var proof   = prover.prove(witness);

        boolean first = ledger.submitTransaction(0, 2, proof.getEncryptedValue(), proof);
        assertThat(first).isTrue();

        Ciphertext fake = crypto.encrypt(BigInteger.valueOf(7), publicKey);

        boolean second = ledger.submitTransaction(0, 2, fake, proof);

        assertThat(second).isFalse();
    }

    // -------------------------------------------------------------------------
    // Homomorphic accumulation
    // -------------------------------------------------------------------------

    @Test
    void should_accumulate_encrypted_values_homomorphically() {
        var w1 = new RangeWitness(BigInteger.valueOf(3), publicKey);
        var p1 = prover.prove(w1);
        ledger.submitTransaction(0, 2, p1.getEncryptedValue(), p1);

        var w2 = new RangeWitness(BigInteger.valueOf(4), publicKey);
        var p2 = prover.prove(w2);
        ledger.submitTransaction(0, 2, p2.getEncryptedValue(), p2);

        Ciphertext state = ledger.getEntry(0, 2);
        BigInteger decrypted = crypto.decryptToGroupElement(state, secretKey);
        int maxPossible = (1 << BIT_LENGTH) * 2;
        BigInteger value = crypto.babyStepGiantStepLog(decrypted, maxPossible, group);

        assertThat(value).isEqualTo(BigInteger.valueOf(7));
    }

    // -------------------------------------------------------------------------
    // Wrong public key
    // -------------------------------------------------------------------------

    @Test
    void should_reject_transaction_with_wrong_public_key() {
        var witness = new RangeWitness(BigInteger.valueOf(5), publicKey);
        var proof   = prover.prove(witness);

        var anotherKeyPair = crypto.keyGen();
        var wrongVerifier = new BitDecompositionRangeVerifier(group, anotherKeyPair.publicKey, 4);
        var wrongLedger   = new Ledger(group, 3, wrongVerifier);

        boolean accepted = wrongLedger.submitTransaction(0, 1, proof.getEncryptedValue(), proof);

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Range proof failure
    // -------------------------------------------------------------------------

    @Test
    void should_reject_invalid_proof() {
        var witness = new RangeWitness(BigInteger.valueOf(5), publicKey);
        var proof   = prover.prove(witness);

        // Corrupt the first bit's Pedersen commitment
        proof.getBitCommitments()[0] = proof.getBitCommitments()[0].add(BigInteger.ONE);

        boolean accepted = ledger.submitTransaction(0, 1, proof.getEncryptedValue(), proof);

        assertThat(accepted).isFalse();
    }
}
