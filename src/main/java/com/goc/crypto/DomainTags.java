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

    /** Tag for the Chaum-Pedersen challenge proving two ciphertexts encrypt the same plaintext. */
    public static final byte[] CIPHERTEXT_EQUIVALENCE_CHALLENGE =
            "CIPHERTEXT_EQUIVALENCE_CHALLENGE".getBytes();

    /** Tag for the value-link proof binding the Pedersen commitment C to the ElGamal ciphertext c2. */
    public static final byte[] VALUE_LINK_CHALLENGE =
            "VALUE_LINK_CHALLENGE".getBytes();

    // ---------------------------------------------------------------------
    // EC (Ristretto255) variants — kept distinct from the DL tags above so
    // proofs cannot be confused across the two groups.
    // ---------------------------------------------------------------------

    public static final byte[] EC_OR_PROOF_CHALLENGE =
            "EC_OR_PROOF_CHALLENGE".getBytes();

    public static final byte[] EC_ENC_UPDATE_DERIVE =
            "EC_ENC_UPDATE_DERIVE".getBytes();

    public static final byte[] EC_BINDING_PROOF_CHALLENGE =
            "EC_BINDING_PROOF_CHALLENGE".getBytes();

    public static final byte[] EC_CIPHERTEXT_EQUIVALENCE_CHALLENGE =
            "EC_CIPHERTEXT_EQUIVALENCE_CHALLENGE".getBytes();

    public static final byte[] EC_VALUE_LINK_CHALLENGE =
            "EC_VALUE_LINK_CHALLENGE".getBytes();
}
