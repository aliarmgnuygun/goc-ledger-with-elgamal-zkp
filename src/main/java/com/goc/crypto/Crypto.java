package com.goc.crypto;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.core.KeyPair;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Crypto {

    private final CryptoGroup group;
    private final SecureRandom random = new SecureRandom();

    public Crypto(CryptoGroup group) {
        this.group = group;
    }

    public KeyPair keyGen() {
        BigInteger x = new BigInteger(group.q.bitLength(), random).mod(group.q);
        BigInteger h = group.pow(group.g, x);
        return new KeyPair(x, h);
    }

    // Additive (exponential) ElGamal
    public Ciphertext encrypt(BigInteger m, BigInteger publicKey) {
        BigInteger r = new BigInteger(group.q.bitLength(), random).mod(group.q);

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

    public BigInteger babyStepGiantStepLog(BigInteger gm, int maxMessage, CryptoGroup group) {
        // 1. Determine step size (m): m = ceil(sqrt(maxMessage))
        int m = (int) Math.ceil(Math.sqrt(maxMessage));
        Map<BigInteger, Integer> babySteps = new HashMap<>();

        // 2. Compute Baby Steps: Store (g^j, j) in a hash map for memory phase
        BigInteger current = BigInteger.ONE; // g^0
        for (int j = 0; j < m; j++) {
            babySteps.putIfAbsent(current, j);
            current = group.mul(current, group.g);
        }

        // 3. Calculate Giant Step multiplier (c): c = (g^m)^(-1) mod p
        BigInteger mBig = BigInteger.valueOf(m);
        BigInteger gToM = group.pow(group.g, mBig);
        BigInteger c = group.inverse(gToM);

        // 4. Giant Steps: Search for a match in the hash map (search phase)
        BigInteger target = gm;
        for (int i = 0; i <= m; i++) {
            if (babySteps.containsKey(target)) {
                // Match found: x = i * m + j
                long x = (long) i * m + babySteps.get(target);
                return BigInteger.valueOf(x);
            }
            // Move to the next giant step: target = target * c mod p
            target = group.mul(target, c);
        }

        throw new IllegalArgumentException("Discrete log not found within the maxMessage bound");
    }

    public BigInteger generateRandomness() {
        return new BigInteger(group.q.bitLength(), random).mod(group.q);
    }
}
