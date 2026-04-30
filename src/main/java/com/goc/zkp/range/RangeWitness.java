package com.goc.zkp.range;

import java.math.BigInteger;

public record RangeWitness(
        BigInteger value,
        BigInteger secretKey,
        BigInteger publicKey
) {}
