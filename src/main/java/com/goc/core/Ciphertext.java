package com.goc.core;

import java.math.BigInteger;

public class Ciphertext {
    public final BigInteger c1;
    public final BigInteger c2;

    public Ciphertext(BigInteger c1, BigInteger c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public Ciphertext multiply(Ciphertext other, CryptoGroup group) {
        return new Ciphertext(
            group.mul(this.c1, other.c1),
            group.mul(this.c2, other.c2)
        );
    }
}