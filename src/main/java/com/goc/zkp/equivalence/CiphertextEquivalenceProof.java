package com.goc.zkp.equivalence;

import com.goc.zkp.Proof;

import java.math.BigInteger;

/**
 * Represents a Chaum-Pedersen Non-Interactive Zero-Knowledge (NIZK) proof
 * verifying that two ElGamal ciphertexts under the same public key encrypt
 * the exact same plaintext.
 *
 * This proof demonstrates ciphertext equivalence using the sender's private
 * key without revealing either the secret key or the underlying plaintext.
 */
public record CiphertextEquivalenceProof(
        BigInteger commitmentK1,
        BigInteger commitmentK2,
        BigInteger responseS
) implements Proof {}
