package com.goc.zkp.range.bitdecomposition;

import java.math.BigInteger;

/**
 * Represents a Chaum-Pedersen Non-Interactive Zero-Knowledge (NIZK) proof
 * used to bind an encrypted update ciphertext to the sender's private key.
 *
 * This proof ensures that the transaction was authorized by the rightful
 * key holder without revealing the underlying secret.
 */
public record BindingProof(
        BigInteger R,
        BigInteger commitmentK1,
        BigInteger commitmentK2,
        BigInteger responseS
) {}
