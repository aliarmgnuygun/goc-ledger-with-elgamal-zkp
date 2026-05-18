package com.goc.crypto;

/**
 * Provides unique tags for cryptographic domain separation.
 *
 * Used in Fiat-Shamir protocols to prevent context confusion by ensuring
 * that hashes for different proofs are always distinct.
 */
public final class DomainTags {

    private DomainTags() {
    }

    public static final byte[] OR_PROOF_CHALLENGE =
            "OR_PROOF_CHALLENGE".getBytes();

    /** Tag for deriving y_exp = H(R) inside Enc_update. */
    public static final byte[] ENC_UPDATE_DERIVE =
            "ENC_UPDATE_DERIVE".getBytes();

    /** Tag for the Chaum-Pedersen challenge that binds Enc_update to the sender's secret key. */
    public static final byte[] BINDING_PROOF_CHALLENGE =
            "BINDING_PROOF_CHALLENGE".getBytes();
}
