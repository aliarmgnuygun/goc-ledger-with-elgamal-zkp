package com.goc.zkp.range;

import com.goc.core.Ciphertext;
import com.goc.zkp.Proof;

public class RangeProof implements Proof {

    private final Ciphertext[] encryptedBits;
    private final Ciphertext encryptedValue;
    private final int bitLength;

    public RangeProof(Ciphertext[] encryptedBits,
                      Ciphertext encryptedValue,
                      int bitLength) {
        this.encryptedBits = encryptedBits;
        this.encryptedValue = encryptedValue;
        this.bitLength = bitLength;
    }

    public Ciphertext[] getEncryptedBits() { return encryptedBits; }
    public Ciphertext getEncryptedValue()  { return encryptedValue; }
    public int getBitLength()              { return bitLength; }
}
