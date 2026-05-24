package com.goc.zkp.range.bitdecomposition.ec;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * EC counterpart of {@link com.goc.zkp.range.bitdecomposition.BindingProof}.
 *
 * Chaum-Pedersen NIZK binding an Enc_update ciphertext to the sender's
 * private key on Ristretto255.
 */
public record ECBindingProof(
        RistrettoElement R,
        RistrettoElement commitmentK1,
        RistrettoElement commitmentK2,
        Scalar           responseS
) {}
