package com.goc.zkp.range.bitdecomposition;

import java.math.BigInteger;

/**
 * Sigma proof that the Pedersen commitment used for the range proof and
 * the ElGamal ciphertext used in the ledger hide the same value v.
 *
 * Statement:  ∃ (v, a, s) such that
 *     c2 = g^v · pk^a     (ElGamal second component)
 *     C  = g^v · h^s      (Pedersen commitment, independent generator h)
 *
 * This is what keeps the range proof meaningful: the range proof bounds
 * the v inside C, and this proof certifies that c2 (what the ledger
 * stores and decrypts) carries that very same v.
 *
 * Fields:
 *   t1, t2 — sigma commitments for the two equations
 *   zv     — response for the shared value v
 *   za     — response for the ElGamal randomness a
 *   zs     — response for the Pedersen randomness s
 */
public record ValueLinkProof(
        BigInteger t1,
        BigInteger t2,
        BigInteger zv,
        BigInteger za,
        BigInteger zs
) {}
