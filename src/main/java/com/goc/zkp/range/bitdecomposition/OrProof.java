package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;

import java.math.BigInteger;

public record OrProof(
        Ciphertext encryptedBit,
        BigInteger commitmentA0,
        BigInteger commitmentD0,
        BigInteger commitmentA1,
        BigInteger commitmentD1,
        BigInteger challengeE0,
        BigInteger challengeE1,
        BigInteger responseZ0,
        BigInteger responseZ1
) {}
