package com.goc.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class FiatShamir {
    private FiatShamir() {}

    public static BigInteger hashToZq(BigInteger q, BigInteger... values) {
        byte[] digest = hash(values);
        return new BigInteger(1, digest).mod(q);
    }

    private static byte[] hash(BigInteger... values) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            for (BigInteger value : values) {
                byte[] bytes = value.toByteArray();
                out.write((bytes.length >>> 24) & 0xFF);
                out.write((bytes.length >>> 16) & 0xFF);
                out.write((bytes.length >>> 8) & 0xFF);
                out.write(bytes.length & 0xFF);
                out.write(bytes, 0, bytes.length);
            }

            md.update(out.toByteArray());
            return md.digest();
        }catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}