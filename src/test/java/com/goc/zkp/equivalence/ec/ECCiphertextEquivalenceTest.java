package com.goc.zkp.equivalence.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.goc.crypto.ec.ECCrypto;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ECCiphertextEquivalenceTest {

    private ECCryptoGroup group;
    private ECCrypto      crypto;
    private ECCiphertextEquivalenceProver   prover;
    private ECCiphertextEquivalenceVerifier verifier;
    private ECKeyPair                       keyPair;

    @BeforeEach
    void setUp() {
        group    = new ECCryptoGroup();
        crypto   = new ECCrypto(group);
        prover   = new ECCiphertextEquivalenceProver(group, crypto);
        verifier = new ECCiphertextEquivalenceVerifier(group);
        keyPair  = crypto.keyGen();
    }

    @Test
    void sameValue_differentRandomness_isAccepted() {
        ECCiphertext ctA = crypto.encrypt(42L, keyPair.publicKey);
        ECCiphertext ctB = crypto.encrypt(42L, keyPair.publicKey);

        var proof = prover.prove(keyPair.secretKey, keyPair.publicKey, ctA, ctB);

        assertThat(verifier.verify(proof, keyPair.publicKey, ctA, ctB)).isTrue();
    }

    @Test
    void differentValues_areRejected() {
        ECCiphertext ctA = crypto.encrypt(42L, keyPair.publicKey);
        ECCiphertext ctB = crypto.encrypt(99L, keyPair.publicKey);

        var proof = prover.prove(keyPair.secretKey, keyPair.publicKey, ctA, ctB);

        assertThat(verifier.verify(proof, keyPair.publicKey, ctA, ctB)).isFalse();
    }

    @Test
    void tamperedResponse_isRejected() {
        ECCiphertext ctA = crypto.encrypt(7L, keyPair.publicKey);
        ECCiphertext ctB = crypto.encrypt(7L, keyPair.publicKey);

        var original = prover.prove(keyPair.secretKey, keyPair.publicKey, ctA, ctB);
        var tampered = new ECCiphertextEquivalenceProof(
                original.commitmentK1(),
                original.commitmentK2(),
                original.responseS().add(Scalar.ONE)
        );

        assertThat(verifier.verify(tampered, keyPair.publicKey, ctA, ctB)).isFalse();
    }

    @Test
    void wrongPublicKey_isRejected() {
        ECCiphertext ctA = crypto.encrypt(5L, keyPair.publicKey);
        ECCiphertext ctB = crypto.encrypt(5L, keyPair.publicKey);

        var proof = prover.prove(keyPair.secretKey, keyPair.publicKey, ctA, ctB);

        RistrettoElement wrong = crypto.keyGen().publicKey;
        assertThat(verifier.verify(proof, wrong, ctA, ctB)).isFalse();
    }
}
