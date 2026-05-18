package com.goc.zkp.range.bitdecomposition;

import java.math.BigInteger;

/**
 * OR-proof that a Pedersen commitment opens to 0 or 1.
 *
 * Statement: commit = h^r  ∨  commit · g^{-1} = h^r
 *
 * Fields:
 *   commitment — the Pedersen commitment commit_i = g^{b_i} · h^{r_i}
 *   a0, a1     — sigma commitments for the two branches
 *   c0, c1     — per-branch challenges (sum equals Fiat-Shamir challenge)
 *   z0, z1     — per-branch responses
 */
public record OrProof(
        BigInteger commitment,
        BigInteger a0,
        BigInteger a1,
        BigInteger c0,
        BigInteger c1,
        BigInteger z0,
        BigInteger z1
) {}
