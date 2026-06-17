package com.goc.core.ec;

import com.weavechain.curve25519.Constants;
import com.weavechain.curve25519.RistrettoElement;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Wrapper around the Ristretto255 prime-order group.
 *
 * Mirrors {@link com.goc.core.CryptoGroup} for symmetry across DL and EC
 * implementations, exposing the base generator. Group arithmetic is
 * performed directly on {@link RistrettoElement} via its native
 * additive API (add / subtract / negate / multiply).
 */
public class ECCryptoGroup {

    /** Canonical Ristretto generator (analogous to "g" in the DL group). */
    public final RistrettoElement g = Constants.RISTRETTO_GENERATOR;

    /**
     * Independent Pedersen generator with unknown discrete log relative to g.
     *
     * Derived "nothing up my sleeve" via Ristretto's hash-to-group
     * (fromUniformBytes of a domain-separated SHA-512 digest). Nobody knows
     * log_g(h), so the Pedersen commitments b·g + r·h built on it are
     * binding — which is what makes the range proof sound. (Using the public
     * key here would hand the trapdoor to the prover and break soundness.)
     */
    public final RistrettoElement h = deriveIndependentGenerator();

    private static RistrettoElement deriveIndependentGenerator() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update("GOC-Pedersen-independent-generator".getBytes(StandardCharsets.UTF_8));
            // fromUniformBytes expects 64 bytes; SHA-512 provides exactly that.
            return RistrettoElement.fromUniformBytes(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }
}
