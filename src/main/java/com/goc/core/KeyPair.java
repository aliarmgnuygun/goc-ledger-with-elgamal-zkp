package com.goc.core;

import java.math.BigInteger;

public class KeyPair {
    public final BigInteger secretKey;
    public final BigInteger publicKey;

    public KeyPair(BigInteger secretKey, BigInteger publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }
}