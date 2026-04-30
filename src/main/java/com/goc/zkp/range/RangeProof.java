package com.goc.zkp.range;

import com.goc.core.Ciphertext;
import com.goc.zkp.Proof;
import com.goc.zkp.range.bitdecomposition.OrProof;
import com.goc.zkp.range.equality.EqualityProof;

public class RangeProof implements Proof {

    private final Ciphertext[] encryptedBits;
    private final OrProof[] bitProofs;
    private final EqualityProof[] keyProofs;
    private final Ciphertext encryptedValue;
    private final int bitLength;

    public RangeProof(Ciphertext[] encryptedBits,
                      OrProof[] bitProofs,
                      EqualityProof[] keyProofs,
                      Ciphertext encryptedValue,
                      int bitLength) {
        this.encryptedBits = encryptedBits;
        this.bitProofs = bitProofs;
        this.keyProofs = keyProofs;
        this.encryptedValue = encryptedValue;
        this.bitLength = bitLength;
    }

    public Ciphertext[] getEncryptedBits() { return encryptedBits; }
    public OrProof[] getBitProofs() { return bitProofs; }
    public EqualityProof[] getKeyProofs() { return keyProofs; }
    public Ciphertext getEncryptedValue()  { return encryptedValue; }
    public int getBitLength()              { return bitLength; }
}
