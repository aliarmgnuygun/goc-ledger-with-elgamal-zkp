package com.goc.zkp.equivalence.ec;

import com.goc.zkp.Proof;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * EC counterpart of {@link com.goc.zkp.equivalence.CiphertextEquivalenceProof}.
 *
 * Chaum-Pedersen NIZK proving that two Ristretto ElGamal ciphertexts
 * under the same public key encrypt the same plaintext, using only
 * the sender's secret key (no knowledge of either randomness required).
 */
public record ECCiphertextEquivalenceProof(
        RistrettoElement commitmentK1,
        RistrettoElement commitmentK2,
        Scalar responseS
) implements Proof {
}
