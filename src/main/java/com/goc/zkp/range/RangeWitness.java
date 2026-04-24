package com.goc.zkp.range;

import java.math.BigInteger;

public record RangeWitness(
        BigInteger value,
        BigInteger randomness,
        BigInteger publicKey
) {}
