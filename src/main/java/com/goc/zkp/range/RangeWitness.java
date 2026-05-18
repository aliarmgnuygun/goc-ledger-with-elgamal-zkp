package com.goc.zkp.range;

import java.math.BigInteger;

/**
 * Witness for the Enc_update-bound range proof.
 *
 * The prover needs the secret key to produce the Chaum-Pedersen binding
 * proof attached to the ciphertext (sender authentication).
 */
public record RangeWitness(
        BigInteger value,
        BigInteger secretKey,
        BigInteger publicKey
) {}
