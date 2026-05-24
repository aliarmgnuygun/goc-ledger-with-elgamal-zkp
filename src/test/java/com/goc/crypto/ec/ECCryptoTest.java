package com.goc.crypto.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.weavechain.curve25519.RistrettoElement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ECCryptoTest {

    private ECCryptoGroup group;
    private ECCrypto      crypto;
    private ECKeyPair     keyPair;

    @BeforeEach
    void setUp() {
        group   = new ECCryptoGroup();
        crypto  = new ECCrypto(group);
        keyPair = crypto.keyGen();
    }

    @Test
    void encrypt_then_decrypt_recovers_value() {
        long message = 42L;
        ECCiphertext ct = crypto.encrypt(message, keyPair.publicKey);

        RistrettoElement decrypted = crypto.decryptToGroupElement(ct, keyPair.secretKey);
        long recovered = crypto.babyStepGiantStepLog(decrypted, 1_000L);

        assertThat(recovered).isEqualTo(message);
    }

    @Test
    void homomorphic_addition_works() {
        ECCiphertext a = crypto.encrypt(10L, keyPair.publicKey);
        ECCiphertext b = crypto.encrypt(15L, keyPair.publicKey);

        ECCiphertext sum = a.add(b);
        RistrettoElement decrypted = crypto.decryptToGroupElement(sum, keyPair.secretKey);
        long recovered = crypto.babyStepGiantStepLog(decrypted, 1_000L);

        assertThat(recovered).isEqualTo(25L);
    }

}
