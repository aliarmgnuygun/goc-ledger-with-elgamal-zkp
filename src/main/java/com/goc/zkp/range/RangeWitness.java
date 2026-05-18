package com.goc.zkp.range;

import java.math.BigInteger;

/**
 * Witness for the range proof.
 *
 * The prover generates ElGamal randomness internally and exposes the
 * resulting ciphertext via {@link RangeProof#getEncryptedValue()}.
 */
public record RangeWitness(
        BigInteger value,
        BigInteger publicKey
) {}
