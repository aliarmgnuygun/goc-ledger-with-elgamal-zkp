package com.goc.zkp.range.ec;

/**
 * EC counterpart of {@link com.goc.zkp.range.RangeProver}.
 */
public interface ECRangeProver {
    ECRangeProof prove(ECRangeWitness witness);
}
