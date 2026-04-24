package com.goc.zkp.range;

import com.goc.zkp.Prover;

public interface RangeProver extends Prover<RangeWitness, RangeProof> {
    RangeProof prove(RangeWitness witness);
}