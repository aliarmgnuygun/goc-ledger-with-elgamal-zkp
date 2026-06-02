package com.goc.zkp.range.bulletproof;

import com.weavechain.zk.bulletproofs.Proof;

/**
 * Wraps a weavechain Bulletproof together with the bit-length the proof
 * was produced for. The encrypted value's Pedersen commitment is held
 * inside the underlying {@link Proof#getCommitment(int)}.
 */
public class BulletproofRangeProof {

    private final Proof proof;
    private final int bitLength;

    public BulletproofRangeProof(Proof proof, int bitLength) {
        this.proof = proof;
        this.bitLength = bitLength;
    }

    public Proof getProof() {
        return proof;
    }

    public int getBitLength() {
        return bitLength;
    }
}
