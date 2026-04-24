package com.goc.zkp.range;

import com.goc.zkp.Verifier;

public interface RangeVerifier extends Verifier<RangeProof> {
    boolean verify(RangeProof proof);
}
