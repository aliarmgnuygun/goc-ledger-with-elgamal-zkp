package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeWitness;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeVerifier;
import com.goc.zkp.range.bitdecomposition.OrProof;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.*;

class BitDecompositionRangeProverTest {

    private CryptoGroup group;
    private Crypto crypto;
    private BitDecompositionRangeProver prover;
    private BitDecompositionRangeVerifier verifier;
    private BigInteger secretKey;
    private BigInteger publicKey;

    @BeforeEach
    void setUp() {
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        group  = new CryptoGroup(p, q, g);
        crypto = new Crypto(group);

        var keyPair = crypto.keyGen();
        secretKey   = keyPair.secretKey;
        publicKey   = keyPair.publicKey;

        prover   = new BitDecompositionRangeProver(group, crypto, 4);
        verifier = new BitDecompositionRangeVerifier(group, publicKey, 4);
    }

    @Test
    void validValue_shouldProduceVerifiableProof() {
        var witness = new RangeWitness(BigInteger.valueOf(6), secretKey, publicKey);
        var proof   = prover.prove(witness);

        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void zero_shouldProduceVerifiableProof() {
        var witness = new RangeWitness(BigInteger.ZERO, secretKey, publicKey);
        var proof   = prover.prove(witness);

        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void maxValue_shouldProduceVerifiableProof() {
        var witness = new RangeWitness(BigInteger.valueOf(15), secretKey, publicKey);
        var proof   = prover.prove(witness);

        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void negativeValue_shouldThrowException() {
        var witness = new RangeWitness(BigInteger.valueOf(-1), secretKey, publicKey);

        assertThatThrownBy(() -> prover.prove(witness))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void outOfRangeValue_shouldThrowException() {
        var witness = new RangeWitness(BigInteger.valueOf(16), secretKey, publicKey);

        assertThatThrownBy(() -> prover.prove(witness))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void manipulatedChallenge_shouldBeRejected() {
        var witness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        // Tamper with the first bit's challenge
        proof.getBitProofs()[0] = new OrProof(
                proof.getBitProofs()[0].encryptedBit(),
                proof.getBitProofs()[0].commitmentA0(),
                proof.getBitProofs()[0].commitmentD0(),
                proof.getBitProofs()[0].commitmentA1(),
                proof.getBitProofs()[0].commitmentD1(),
                proof.getBitProofs()[0].challengeE0().add(BigInteger.ONE),
                proof.getBitProofs()[0].challengeE1(),
                proof.getBitProofs()[0].responseZ0(),
                proof.getBitProofs()[0].responseZ1()
        );

        assertThat(verifier.verify(proof)).isFalse();
    }

    @Test
    void wrongPublicKey_shouldBeRejected() {
        var witness        = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof          = prover.prove(witness);
        var anotherKeyPair = crypto.keyGen();
        var wrongVerifier  = new BitDecompositionRangeVerifier(group, anotherKeyPair.publicKey, 4);

        assertThat(wrongVerifier.verify(proof)).isFalse();
    }

    @Test
    void bitLengthMismatch_shouldBeRejected() {
        var witness      = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof        = prover.prove(witness);
        var longVerifier = new BitDecompositionRangeVerifier(group, publicKey, 8);

        assertThat(longVerifier.verify(proof)).isFalse();
    }

    @Test
    void manipulatedAggregatedValue_shouldBeRejected() {
        var witness = new RangeWitness(BigInteger.valueOf(7), secretKey, publicKey);
        var proof   = prover.prove(witness);

        var corruptedValue = new Ciphertext(
                proof.getEncryptedValue().c1.add(BigInteger.ONE), // fake
                proof.getEncryptedValue().c2
        );

        // Keep all the individual bit proofs the same, but change the final aggregated ciphertext to something that doesn't match the bits
        var corruptedProof = new RangeProof(
                proof.getEncryptedBits(),
                proof.getBitProofs(),
                proof.getKeyProofs(),
                corruptedValue,
                proof.getBitLength()
        );

        assertThat(verifier.verify(corruptedProof)).isFalse();
    }
}
