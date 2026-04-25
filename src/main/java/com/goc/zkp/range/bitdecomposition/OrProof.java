package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;

import java.math.BigInteger;

class OrProof {

    final Ciphertext encryptedBits;

    final BigInteger commitmentA0;
    final BigInteger commitmentD0;

    final BigInteger commitmentA1;
    final BigInteger commitmentD1;

    final BigInteger challengeE0;
    final BigInteger challengeE1;

    final BigInteger responseZ0;
    final BigInteger responseZ1;

    OrProof(Ciphertext encryptedBits,
            BigInteger commitmentA0, BigInteger commitmentD0,
            BigInteger commitmentA1, BigInteger commitmentD1,
            BigInteger challengeE0, BigInteger challengeE1,
            BigInteger responseZ0, BigInteger responseZ1) {
        this.encryptedBits = encryptedBits;
        this.commitmentA0 = commitmentA0;
        this.commitmentD0 = commitmentD0;
        this.commitmentA1 = commitmentA1;
        this.commitmentD1 = commitmentD1;
        this.challengeE0 = challengeE0;
        this.challengeE1 = challengeE1;
        this.responseZ0 = responseZ0;
        this.responseZ1 = responseZ1;
    }
}
