package com.goc.zkp.range.bitdecomposition.ec;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * EC counterpart of {@link com.goc.zkp.range.bitdecomposition.OrProof}.
 *
 * OR-proof that a Ristretto Pedersen commitment opens to 0 or 1.
 * Statement:  commit = r·H  ∨  commit − G = r·H
 *
 *   commitment — the Pedersen commitment   bit·G + r·H
 *   a0, a1     — sigma commitments for the two branches
 *   c0, c1     — per-branch challenges (sum equals Fiat-Shamir challenge)
 *   z0, z1     — per-branch responses
 */
public record ECOrProof(
        RistrettoElement commitment,
        RistrettoElement a0,
        RistrettoElement a1,
        Scalar c0,
        Scalar c1,
        Scalar z0,
        Scalar z1
) {}
