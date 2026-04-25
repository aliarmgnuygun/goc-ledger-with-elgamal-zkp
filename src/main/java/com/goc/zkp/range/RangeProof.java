package com.goc.zkp.range;

import com.goc.core.Ciphertext;
import com.goc.zkp.Proof;
import com.goc.zkp.range.bitdecomposition.OrProof;

public class RangeProof implements Proof {

    private final Ciphertext[] encryptedBits;
    private final OrProof[] bitProofs;
    private final Ciphertext encryptedValue;
    private final int bitLength;

    public RangeProof(Ciphertext[] encryptedBits,
                      OrProof[] bitProofs,
                      Ciphertext encryptedValue,
                      int bitLength) {
        this.encryptedBits = encryptedBits;
        this.bitProofs = bitProofs;
        this.encryptedValue = encryptedValue;
        this.bitLength = bitLength;
    }

    public Ciphertext[] getEncryptedBits() { return encryptedBits; }
    public OrProof[] getBitProofs() { return bitProofs; }
    public Ciphertext getEncryptedValue()  { return encryptedValue; }
    public int getBitLength()              { return bitLength; }
}
