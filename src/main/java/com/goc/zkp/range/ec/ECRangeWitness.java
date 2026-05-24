package com.goc.zkp.range.ec;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import java.math.BigInteger;

/**
 * Inputs the sender provides to build an EC range proof: the value she
 * wants to encrypt plus her own key pair. The secret key is needed to
 * sign the ciphertext via the binding proof.
 *
 * The value is a BigInteger so the proof can cover any bit length up to
 * the Ristretto scalar order (parity with the DL counterpart).
 */
public record ECRangeWitness(
        BigInteger value,
        Scalar secretKey,
        RistrettoElement publicKey
) {}
