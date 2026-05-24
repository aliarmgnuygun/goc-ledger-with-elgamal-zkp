package com.goc.zkp.range.ec;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * Inputs the sender provides to build an EC range proof: the value she
 * wants to encrypt plus her own key pair. The secret key is needed to
 * sign the ciphertext via the binding proof.
 */
public record ECRangeWitness(
        long value,
        Scalar secretKey,
        RistrettoElement publicKey
) {}
