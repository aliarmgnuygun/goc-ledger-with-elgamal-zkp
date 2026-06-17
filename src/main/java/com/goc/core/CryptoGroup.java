package com.goc.core;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CryptoGroup {
    public final BigInteger p; // prime modulus
    public final BigInteger q; // group order
    public final BigInteger g; // generator

    /**
     * Independent Pedersen generator with unknown discrete log relative to g.
     *
     * Derived deterministically ("nothing up my sleeve") by hashing a fixed
     * domain string together with the group parameters and squaring the
     * result into the order-q subgroup. Because nobody knows log_g(h), the
     * Pedersen commitments g^v · h^r built on it are binding — which is what
     * makes the range proof sound. (Using the public key here instead would
     * leak the trapdoor to the prover and break soundness.)
     */
    public final BigInteger h;

    public CryptoGroup(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.h = deriveIndependentGenerator(p, g);
    }

    public BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(p); // (a*b) mod(p)
    }

    public BigInteger pow(BigInteger base, BigInteger exp) {
        return base.modPow(exp, p); //
    }

    public BigInteger inverse(BigInteger a) {
        return a.modInverse(p);
    }

    /**
     * Hashes a domain string + (p, g) to a field element and squares it into
     * the quadratic-residue subgroup of order q (valid for safe primes
     * p = 2q + 1). Squaring guarantees membership in the subgroup; the hash
     * input guarantees nobody knows the resulting element's log base g.
     */
    private static BigInteger deriveIndependentGenerator(BigInteger p, BigInteger g) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("GOC-Pedersen-independent-generator".getBytes(StandardCharsets.UTF_8));
            md.update(p.toByteArray());
            md.update(g.toByteArray());

            BigInteger candidate = new BigInteger(1, md.digest()).mod(p);
            BigInteger h = candidate.modPow(BigInteger.TWO, p); // land in order-q subgroup
            // Astronomically unlikely, but guard against the degenerate elements.
            if (h.equals(BigInteger.ONE) || h.equals(g)) {
                h = candidate.add(BigInteger.ONE).modPow(BigInteger.TWO, p);
            }
            return h;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
