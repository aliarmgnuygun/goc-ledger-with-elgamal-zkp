package com.goc.zkp.range.bitdecomposition.ec;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * EC counterpart of {@link com.goc.zkp.range.bitdecomposition.ValueLinkProof}.
 *
 * Sigma proof that the Pedersen commitment C and the ElGamal ciphertext
 * c2 hide the same value v on Ristretto255:
 *     c2 = v·G + a·pk
 *     C  = v·G + s·H     (H = independent generator)
 */
public record ECValueLinkProof(
        RistrettoElement t1,
        RistrettoElement t2,
        Scalar           zv,
        Scalar           za,
        Scalar           zs
) {}
