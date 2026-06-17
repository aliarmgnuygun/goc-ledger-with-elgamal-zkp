package com.goc.zkp.range.bitdecomposition.ec;

import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.goc.crypto.ec.ECCrypto;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeWitness;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ECBitDecompositionRangeProverTest {

    private ECCryptoGroup group;
    private ECCrypto      crypto;
    private ECBitDecompositionRangeProver   prover;
    private ECBitDecompositionRangeVerifier verifier;
    private RistrettoElement publicKey;
    private Scalar           secretKey;

    @BeforeEach
    void setUp() {
        group  = new ECCryptoGroup();
        crypto = new ECCrypto(group);

        ECKeyPair keyPair = crypto.keyGen();
        publicKey = keyPair.publicKey;
        secretKey = keyPair.secretKey;

        prover   = new ECBitDecompositionRangeProver(group, crypto, 4);
        verifier = new ECBitDecompositionRangeVerifier(group, 4);
    }

    @Test
    void validValue_shouldProduceVerifiableProof() {
        var witness = new ECRangeWitness(BigInteger.valueOf(6), secretKey, publicKey);
        var proof   = prover.prove(witness);

        assertThat(verifier.verify(proof, publicKey)).isTrue();
    }

    @Test
    void zero_shouldProduceVerifiableProof() {
        var witness = new ECRangeWitness(BigInteger.ZERO, secretKey, publicKey);
        var proof   = prover.prove(witness);

        assertThat(verifier.verify(proof, publicKey)).isTrue();
    }

    @Test
    void maxValue_shouldProduceVerifiableProof() {
        var witness = new ECRangeWitness(BigInteger.valueOf(15), secretKey, publicKey);
        var proof   = prover.prove(witness);

        assertThat(verifier.verify(proof, publicKey)).isTrue();
    }

    @Test
    void negativeValue_shouldThrowException() {
        var witness = new ECRangeWitness(BigInteger.valueOf(-1), secretKey, publicKey);

        assertThatThrownBy(() -> prover.prove(witness))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void outOfRangeValue_shouldThrowException() {
        var witness = new ECRangeWitness(BigInteger.valueOf(16), secretKey, publicKey);

        assertThatThrownBy(() -> prover.prove(witness))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void manipulatedChallenge_shouldBeRejected() {
        var witness = new ECRangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        ECOrProof original = proof.getBitProofs()[0];
        proof.getBitProofs()[0] = new ECOrProof(
                original.commitment(),
                original.a0(),
                original.a1(),
                original.c0().add(Scalar.ONE),
                original.c1(),
                original.z0(),
                original.z1()
        );

        assertThat(verifier.verify(proof, publicKey)).isFalse();
    }

    @Test
    void wrongPublicKey_shouldBeRejected() {
        var witness = new ECRangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        RistrettoElement wrong = crypto.keyGen().publicKey;
        assertThat(verifier.verify(proof, wrong)).isFalse();
    }

    @Test
    void manipulatedBitCommitment_shouldBeRejected() {
        var witness = new ECRangeWitness(BigInteger.valueOf(10), secretKey, publicKey);
        var proof   = prover.prove(witness);

        proof.getBitCommitments()[0] = proof.getBitCommitments()[0].add(group.g);

        assertThat(verifier.verify(proof, publicKey)).isFalse();
    }

    @Test
    void sixtyFourBitMaxValue_shouldProduceVerifiableProof() {
        // Verifies the BigInteger refactor: values larger than Long.MAX_VALUE
        // can be range-proved (would have overflowed the previous long-based prover).
        var bigProver   = new ECBitDecompositionRangeProver(group, crypto, 64);
        var bigVerifier = new ECBitDecompositionRangeVerifier(group, 64);

        BigInteger maxValue = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE); // 2^64 - 1
        var witness = new ECRangeWitness(maxValue, secretKey, publicKey);
        var proof   = bigProver.prove(witness);

        assertThat(bigVerifier.verify(proof, publicKey)).isTrue();
    }

    @Test
    void manipulatedBindingProof_shouldBeRejected() {
        var witness = new ECRangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        ECBindingProof original = proof.getBindingProof();
        ECBindingProof tampered = new ECBindingProof(
                original.R(),
                original.commitmentK1(),
                original.commitmentK2(),
                original.responseS().add(Scalar.ONE)
        );

        ECRangeProof spliced = new ECRangeProof(
                proof.getBitCommitments(),
                proof.getBitProofs(),
                proof.getPedersenCommitment(),
                proof.getEncryptedValue(),
                proof.getValueLinkProof(),
                tampered,
                proof.getBitLength()
        );

        assertThat(verifier.verify(spliced, publicKey)).isFalse();
    }
}
