package com.goc.zkp.range.equality;

import java.math.BigInteger;

/**
 * Secret input for EqualityProver.
 *
 * x  →  the discrete log known to the prover
 * g1 →  first base:  a = g1^x
 * g2 →  second base: b = g2^x
 * a  →  g1^x  (public)
 * b  →  g2^x  (public)
 */
public record EqualityWitness(
        BigInteger x,
        BigInteger g1,
        BigInteger g2,
        BigInteger a,
        BigInteger b
) {}