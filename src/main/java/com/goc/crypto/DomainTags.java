package com.goc.crypto;

/**
 * Provides unique tags for cryptographic domain separation.
 *
 * Used in Fiat-Shamir protocols to prevent "context confusion" by ensuring
 * that hashes for different proofs (e.g., OR-Proof vs. Equality-Proof)
 * are always distinct.
 */
public final class DomainTags {

    private DomainTags() {
    }

    public static final byte[] OR_PROOF_CHALLENGE =
            "OR_PROOF_CHALLENGE".getBytes();

    public static final byte[] EQUALITY_PROOF_CHALLENGE =
            "EQUALITY_PROOF_CHALLENGE".getBytes();

    public static final byte[] BIT_DECOMPOSITION_BASE =
            "BIT_DECOMPOSITION_BASE".getBytes();
}