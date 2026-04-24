package com.goc.core;

import java.math.BigInteger;

public class CryptoGroup {
    public final BigInteger p; // prime modulus
    public final BigInteger q; // group order
    public final BigInteger g; // generator

    public CryptoGroup(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    public BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(p); // (a*b) mod(p)
    }

    public BigInteger pow(BigInteger base, BigInteger exp) {
        return base.modPow(exp, p); //
    }

    public BigInteger inverse(BigInteger a) {
        return a.modInverse(p);
    }
}
