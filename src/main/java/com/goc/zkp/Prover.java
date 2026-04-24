package com.goc.zkp;

public interface Prover<W, P extends Proof> {
    P prove(W witness);
}