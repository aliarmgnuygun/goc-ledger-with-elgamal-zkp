package com.goc.zkp;

public interface Verifier<P extends Proof> {
    boolean verify(P proof);
}
