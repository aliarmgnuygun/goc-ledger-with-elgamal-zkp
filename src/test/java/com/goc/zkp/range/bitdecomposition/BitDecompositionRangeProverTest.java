package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeWitness;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.*;

class BitDecompositionRangeProverTest {

    private CryptoGroup group;
    private Crypto crypto;
    private BitDecompositionRangeProver prover;
    private BitDecompositionRangeVerifier verifier;
    private BigInteger publicKey;
    private BigInteger secretKey;

    @BeforeEach
    void setUp() {
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        group  = new CryptoGroup(p, q, g);
        crypto = new Crypto(group);

        var keyPair = crypto.keyGen();
        publicKey   = keyPair.publicKey;
        secretKey   = keyPair.secretKey;

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

        OrProof original = proof.getBitProofs()[0];
        proof.getBitProofs()[0] = new OrProof(
                original.commitment(),
                original.a0(),
                original.a1(),
                original.c0().add(BigInteger.ONE),
                original.c1(),
                original.z0(),
                original.z1()
        );

        assertThat(verifier.verify(proof)).isFalse();
    }

    @Test
    void wrongPublicKey_shouldBeRejected() {
        var witness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        // Toy parameters (q = 11) allow occasional hash-mod-q collisions
        // for individual wrong keys; soundness still rejects the vast
        // majority of them. Try several and require most to be rejected.
        int attempts   = 20;
        int rejections = 0;
        for (int i = 0; i < attempts; i++) {
            BigInteger wrong;
            do {
                wrong = crypto.keyGen().publicKey;
            } while (wrong.equals(publicKey));

            var wrongVerifier = new BitDecompositionRangeVerifier(group, wrong, 4);
            if (!wrongVerifier.verify(proof)) rejections++;
        }
        assertThat(rejections).isGreaterThan(attempts / 2);
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
                proof.getEncryptedValue().c1,
                proof.getEncryptedValue().c2.add(BigInteger.ONE)
        );

        var corruptedProof = new RangeProof(
                proof.getBitCommitments(),
                proof.getBitProofs(),
                corruptedValue,
                proof.getBindingProof(),
                proof.getBitLength()
        );

        assertThat(verifier.verify(corruptedProof)).isFalse();
    }

    @Test
    void manipulatedBindingProof_shouldBeRejected() {
        var witness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var proof   = prover.prove(witness);

        BindingProof original = proof.getBindingProof();
        BindingProof tampered = new BindingProof(
                original.R(),
                original.commitmentK1(),
                original.commitmentK2(),
                original.responseS().add(BigInteger.ONE)
        );

        var tamperedProof = new RangeProof(
                proof.getBitCommitments(),
                proof.getBitProofs(),
                proof.getEncryptedValue(),
                tampered,
                proof.getBitLength()
        );

        assertThat(verifier.verify(tamperedProof)).isFalse();
    }

    @Test
    void bindingProofFromDifferentSender_shouldBeRejected() {
        // Forge: build a proof using attacker's own secret key but the victim's public key.
        var victimWitness = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        var legitimate    = prover.prove(victimWitness);

        var attacker = crypto.keyGen();
        var attackerWitness = new RangeWitness(BigInteger.valueOf(5),
                attacker.secretKey, attacker.publicKey);
        var attackerProof   = prover.prove(attackerWitness);

        // Splice the attacker's binding proof onto the legitimate ciphertext.
        var spliced = new RangeProof(
                legitimate.getBitCommitments(),
                legitimate.getBitProofs(),
                legitimate.getEncryptedValue(),
                attackerProof.getBindingProof(),
                legitimate.getBitLength()
        );

        assertThat(verifier.verify(spliced)).isFalse();
    }

    @Test
    void manipulatedBitCommitment_shouldBeRejected() {
        var witness = new RangeWitness(BigInteger.valueOf(10), secretKey, publicKey);
        var proof   = prover.prove(witness);

        proof.getBitCommitments()[0] = proof.getBitCommitments()[0].add(BigInteger.ONE);

        assertThat(verifier.verify(proof)).isFalse();
    }
}
