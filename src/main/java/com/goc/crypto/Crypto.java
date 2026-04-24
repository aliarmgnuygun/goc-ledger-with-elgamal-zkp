package com.goc.crypto;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.core.KeyPair;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Crypto {

    private final CryptoGroup group;
    private final SecureRandom random = new SecureRandom();

    public Crypto(CryptoGroup group) {
        this.group = group;
    }

    public KeyPair keyGen() {
        BigInteger x = new BigInteger(group.g.bitLength(), random).mod(group.q);
        BigInteger h = group.pow(group.g, x);
        return new KeyPair(x, h);
    }

    // Additive (exponential) ElGamal
    public Ciphertext encrypt(BigInteger m, BigInteger publicKey) {
        BigInteger r = new BigInteger(group.g.bitLength(), random).mod(group.q); // random number r

        BigInteger c1 = group.pow(group.g, r);
        BigInteger c2 = group.mul(
                group.pow(publicKey, r),
                group.pow(group.g, m)
        );

        return new Ciphertext(c1, c2);
    }

    // Decrypts to g^m
    public BigInteger decryptToGroupElement(Ciphertext c, BigInteger secretKey) {
        BigInteger s = group.pow(c.c1, secretKey);
        return group.mul(c.c2, group.inverse(s));
    }

    // Brute-force discrete log (small messages only!)
    public BigInteger bruteForceLog(BigInteger gm, int maxMessage) {
        BigInteger current = BigInteger.ONE; // g^0

        for (int i = 0; i <= maxMessage; i++) {
            if (current.equals(gm)) {
                return BigInteger.valueOf(i);
            }
            current = group.mul(current, group.g);
        }
        throw new IllegalArgumentException("Discrete log not found");
    }

    public BigInteger generateRandomness() {
        return new BigInteger(group.q.bitLength(), random).mod(group.q);
    }
}
