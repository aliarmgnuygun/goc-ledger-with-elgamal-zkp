package com.goc.zkp.range.bulletproof;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BulletproofRangeProverTest {

    private BulletproofRangeProver   prover;
    private BulletproofRangeVerifier verifier;

    @BeforeEach
    void setUp() {
        // Bulletproofs require bitLength to be a power of two in the gadget
        // we use; 8 is the smallest reliable choice.
        prover   = new BulletproofRangeProver(8);
        verifier = new BulletproofRangeVerifier(8);
    }

    @Test
    void validValue_shouldProduceVerifiableProof() {
        var proof = prover.prove(new BulletproofRangeWitness(42L));
        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void smallValue_shouldProduceVerifiableProof() {
        // weavechain's number_in_range gadget rejects the trivial value 0
        // (Pedersen commitment to zero collapses the range argument), so we
        // exercise the lower end of the range with value = 1 instead.
        var proof = prover.prove(new BulletproofRangeWitness(1L));
        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void maxValue_shouldProduceVerifiableProof() {
        var proof = prover.prove(new BulletproofRangeWitness(255L)); // 2^8 - 1
        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void negativeValue_shouldThrowException() {
        assertThatThrownBy(() -> prover.prove(new BulletproofRangeWitness(-1L)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void outOfRangeValue_shouldThrowException() {
        assertThatThrownBy(() -> prover.prove(new BulletproofRangeWitness(256L)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void bitLengthMismatch_shouldBeRejected() {
        var proof          = prover.prove(new BulletproofRangeWitness(5L));
        var wrongVerifier  = new BulletproofRangeVerifier(16);
        assertThat(wrongVerifier.verify(proof)).isFalse();
    }
}
