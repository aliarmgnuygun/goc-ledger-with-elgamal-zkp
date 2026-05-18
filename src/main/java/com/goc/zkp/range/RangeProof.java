package com.goc.zkp.range;

import com.goc.core.Ciphertext;
import com.goc.zkp.Proof;
import com.goc.zkp.range.bitdecomposition.OrProof;

import java.math.BigInteger;

/**
 * Bit-decomposition range proof.
 *
 * Holds:
 *   - one Pedersen commitment per bit:  commit_i = g^{b_i} · h^{r_i}
 *   - one OR-proof per bit proving b_i ∈ {0, 1}
 *   - the ElGamal ciphertext  Enc(v) = (g^r, g^v · h^r)
 *     whose c2 component equals  Π commit_i^{2^i}.
 */
public class RangeProof implements Proof {

    private final BigInteger[] bitCommitments;
    private final OrProof[] bitProofs;
    private final Ciphertext encryptedValue;
    private final int bitLength;

    public RangeProof(BigInteger[] bitCommitments,
                      OrProof[] bitProofs,
                      Ciphertext encryptedValue,
                      int bitLength) {
        this.bitCommitments = bitCommitments;
        this.bitProofs = bitProofs;
        this.encryptedValue = encryptedValue;
        this.bitLength = bitLength;
    }

    public BigInteger[] getBitCommitments() { return bitCommitments; }
    public OrProof[] getBitProofs() { return bitProofs; }
    public Ciphertext getEncryptedValue() { return encryptedValue; }
    public int getBitLength() { return bitLength; }
}
