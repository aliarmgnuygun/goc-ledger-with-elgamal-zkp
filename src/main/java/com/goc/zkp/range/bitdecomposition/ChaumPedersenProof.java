package com.goc.zkp.range.bitdecomposition;

import java.math.BigInteger;

public record ChaumPedersenProof(
        BigInteger commitmentT1,
        BigInteger commitmentT2,
        BigInteger responseS,
        BigInteger publicZ
) {}
