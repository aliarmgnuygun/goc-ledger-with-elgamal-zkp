package com.goc.zkp.range.equality;

import com.goc.zkp.Proof;
import java.math.BigInteger;

/**
 * Proof of equality of discrete logarithms.
 *
 * Proves that two public values (a, b) share the same discrete log x:
 *   a = g1^x  and  b = g2^x
 *
 * without revealing x.
 */
public record EqualityProof(
        BigInteger g1,           // first base
        BigInteger g2,           // second base
        BigInteger a,            // g1^x
        BigInteger b,            // g2^x
        BigInteger commitmentK1, // g1^w  (prover's first commitment)
        BigInteger commitmentK2, // g2^w  (prover's second commitment)
        BigInteger responseZ     // w + challenge * x  (mod q)
) implements Proof {}