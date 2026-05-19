package com.goc.zkp.range;

import java.math.BigInteger;

public interface RangeVerifier {
    boolean verify(RangeProof proof, BigInteger publicKey);
}
