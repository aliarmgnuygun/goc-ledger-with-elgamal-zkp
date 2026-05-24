package com.goc.crypto.ec;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Fiat-Shamir helper for the EC (Ristretto255) protocols.
 *
 * Serializes the domain tag and an arbitrary mix of Ristretto points and
 * scalars, hashes them with SHA-512, and reduces the digest into a
 * uniform Scalar in [0, ℓ).
 */
public final class ECFiatShamir {

    private ECFiatShamir() {}

    /**
     * Hashes the given values (RistrettoElement or Scalar) together with
     * the domain tag and returns a Scalar in [0, ℓ).
     */
    public static Scalar hashToScalar(byte[] domainTag, Object... values) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeLengthPrefixed(out, domainTag);
            for (Object v : values) {
                writeLengthPrefixed(out, toBytes(v));
            }
            // SHA-512 produces 64 bytes, exactly what fromBytesModOrderWide needs.
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(out.toByteArray());
            return Scalar.fromBytesModOrderWide(md.digest());
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalStateException("Hashing failed", e);
        }
    }

    private static byte[] toBytes(Object value) {
        if (value instanceof Scalar s)            return s.toByteArray();
        if (value instanceof RistrettoElement p)  return p.compress().toByteArray();
        if (value instanceof byte[] b)            return b;
        throw new IllegalArgumentException(
                "ECFiatShamir does not know how to serialize: " + value.getClass());
    }

    /** Canonical [4-byte length][payload] framing. */
    private static void writeLengthPrefixed(ByteArrayOutputStream out, byte[] data) throws IOException {
        out.write((data.length >>> 24) & 0xFF);
        out.write((data.length >>> 16) & 0xFF);
        out.write((data.length >>> 8) & 0xFF);
        out.write(data.length & 0xFF);
        out.write(data, 0, data.length);
    }
}
