package com.goc.crypto.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * EC ElGamal over Ristretto255 — the counterpart to {@link com.goc.crypto.Crypto}.
 *
 * Encryption  : c1 = r · G, c2 = m · G + r · H
 * Decryption  : c2 − sk · c1  →  m · G   (caller resolves the discrete log
 *               via brute force or baby-step giant-step for small m)
 */
public class ECCrypto {

    private final ECCryptoGroup group;
    private final SecureRandom random = new SecureRandom();

    public ECCrypto(ECCryptoGroup group) {
        this.group = group;
    }

    public ECKeyPair keyGen() {
        Scalar sk = generateRandomness();
        RistrettoElement pk = group.g.multiply(sk);
        return new ECKeyPair(sk, pk);
    }

    /** Encrypts a non-negative integer message under the receiver's public key. */
    public ECCiphertext encrypt(long message, RistrettoElement publicKey) {
        Scalar r = generateRandomness();
        Scalar m = scalarFromLong(message);

        RistrettoElement c1 = group.g.multiply(r);
        RistrettoElement c2 = group.g.multiply(m).add(publicKey.multiply(r));
        return new ECCiphertext(c1, c2);
    }

    /** Returns m · G; caller is responsible for solving the discrete log to recover m. */
    public RistrettoElement decryptToGroupElement(ECCiphertext ct, Scalar secretKey) {
        return ct.c2.subtract(ct.c1.multiply(secretKey));
    }

    /**
     * Baby-step giant-step discrete log on m · G — used by the receiver to
     * recover small plaintexts. Memory: O(√maxMessage). Time: O(√maxMessage).
     */
    public long babyStepGiantStepLog(RistrettoElement target, long maxMessage) {
        long m = (long) Math.ceil(Math.sqrt((double) maxMessage));

        // Baby steps: store (j · G) → j for j = 0 .. m-1
        Map<RistrettoElement, Long> babySteps = new HashMap<>();
        RistrettoElement current = RistrettoElement.IDENTITY;
        for (long j = 0; j < m; j++) {
            babySteps.putIfAbsent(current, j);
            current = current.add(group.g);
        }

        // Giant step: subtract m · G repeatedly until we hit a baby step.
        RistrettoElement giantStep = group.g.multiply(scalarFromLong(m));
        RistrettoElement query     = target;
        for (long i = 0; i <= m; i++) {
            Long match = babySteps.get(query);
            if (match != null) return Math.multiplyExact(i, m) + match;
            query = query.subtract(giantStep);
        }
        throw new IllegalArgumentException("Discrete log not found within the maxMessage bound");
    }

    /**
     * Samples a random scalar uniformly in [0, ℓ) using 64 random bytes
     * (rejection-free thanks to wide reduction).
     */
    public Scalar generateRandomness() {
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        return Scalar.fromBytesModOrderWide(bytes);
    }

    /** Converts a non-negative long into a Ristretto Scalar. */
    public static Scalar scalarFromLong(long value) {
        if (value < 0) throw new IllegalArgumentException("Scalar values must be non-negative");
        byte[] bytes = new byte[32];               // little-endian
        long v = value;
        for (int i = 0; i < 8 && v != 0; i++) {
            bytes[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        return Scalar.fromCanonicalBytes(bytes);
    }
}
