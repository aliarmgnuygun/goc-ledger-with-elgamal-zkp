package com.goc.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class FiatShamir {
    private FiatShamir() {
    }

    /**
     * Hashes values to an element in Zq with domain separation.
     *
     * @param q         The modulus
     * @param domainTag The unique identifier from {@link DomainTags}
     * @param values    The values to be hashed
     * @return A BigInteger in the range [0, q-1]
     */
    public static BigInteger hashToZq(BigInteger q, byte[] domainTag, BigInteger... values) {
        byte[] digest = hash(domainTag, values);
        return new BigInteger(1, digest).mod(q);
    }

    private static byte[] hash(byte[] domainTag, BigInteger... values) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            writeLengthPrefixed(out, domainTag);

            for (BigInteger value : values) {
                writeLengthPrefixed(out, value.toByteArray());
            }

            md.update(out.toByteArray());
            return md.digest();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalStateException("Hashing failed", e);
        }
    }

    /**
     * Helper method to implement canonical serialization:
     * [4-byte length][data]
     */
    private static void writeLengthPrefixed(ByteArrayOutputStream out, byte[] data) throws IOException {
        out.write((data.length >>> 24) & 0xFF);
        out.write((data.length >>> 16) & 0xFF);
        out.write((data.length >>> 8) & 0xFF);
        out.write(data.length & 0xFF);
        out.write(data, 0, data.length);
    }
}