package com.goc.ledger;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.ledger.Ledger;
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
        var witness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
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
        var witness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        // Fake ciphertext (different value)
        Ciphertext fake = crypto.encrypt(BigInteger.valueOf(10), publicKey);

        boolean accepted = ledger.submitTransaction(0, 1, fake, proof);

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Proof tampering
    // -------------------------------------------------------------------------

    @Test
    void should_reject_when_proof_is_tampered() {
        var witness = new RangeWitness(BigInteger.valueOf(6), secretKey, publicKey);
        var proof   = prover.prove(witness);

        // Manipulate aggregated ciphertext inside proof
        RangeProof tampered = new RangeProof(
                proof.getEncryptedBits(),
                proof.getBitProofs(),
                proof.getKeyProofs(),
                new Ciphertext(
                        proof.getEncryptedValue().c1.add(BigInteger.ONE),
                        proof.getEncryptedValue().c2
                ),
                proof.getBitLength()
        );

        boolean accepted = ledger.submitTransaction(0, 1, tampered.getEncryptedValue(), tampered);

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // Replay attack (same proof reused with different ciphertext)
    // -------------------------------------------------------------------------

    @Test
    void should_reject_replay_attack_using_same_proof_with_different_ciphertext() {
        var witness = new RangeWitness(BigInteger.valueOf(4), secretKey, publicKey);
        var proof   = prover.prove(witness);

        // First valid submission
        boolean first = ledger.submitTransaction(0, 2, proof.getEncryptedValue(), proof);
        assertThat(first).isTrue();

        // Replay attack: reuse proof but change ciphertext
        Ciphertext fake = crypto.encrypt(BigInteger.valueOf(7), publicKey);

        boolean second = ledger.submitTransaction(0, 2, fake, proof);

        assertThat(second).isFalse();
    }

    // -------------------------------------------------------------------------
    // Homomorphic accumulation
    // -------------------------------------------------------------------------

    @Test
    void should_accumulate_encrypted_values_homomorphically() {
        var w1 = new RangeWitness(BigInteger.valueOf(3), secretKey, publicKey);
        var p1 = prover.prove(w1);
        ledger.submitTransaction(0, 2, p1.getEncryptedValue(), p1);

        var w2 = new RangeWitness(BigInteger.valueOf(4), secretKey, publicKey);
        var p2 = prover.prove(w2);
        ledger.submitTransaction(0, 2, p2.getEncryptedValue(), p2);

        Ciphertext state = ledger.getEntry(0, 2);
        BigInteger decrypted = crypto.decryptToGroupElement(state, secretKey);
        int maxPossible = (1 << BIT_LENGTH) * 2;
        BigInteger value = crypto.bruteForceLog(decrypted, maxPossible);

        assertThat(value).isEqualTo(BigInteger.valueOf(7));
    }

    // -------------------------------------------------------------------------
    // Wrong public key
    // -------------------------------------------------------------------------

    @Test
    void should_reject_transaction_with_wrong_public_key() {
        var witness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        var anotherKeyPair = crypto.keyGen();
        var wrongVerifier = new BitDecompositionRangeVerifier(group, anotherKeyPair.publicKey, 4);
        var wrongLedger   = new Ledger(group, 3, wrongVerifier);

        boolean accepted = wrongLedger.submitTransaction(0, 1, proof.getEncryptedValue(), proof);

        assertThat(accepted).isFalse();
    }

    // -------------------------------------------------------------------------
    // RANGE PROOF FAILURE
    // -------------------------------------------------------------------------

    @Test
    void should_reject_invalid_proof() {
        var witness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        // Break first bit ciphertext
        proof.getEncryptedBits()[0] = new Ciphertext(
                proof.getEncryptedBits()[0].c1.add(BigInteger.ONE),
                proof.getEncryptedBits()[0].c2
        );

        boolean accepted = ledger.submitTransaction(0, 1, proof.getEncryptedValue(), proof);

        assertThat(accepted).isFalse();
    }
}