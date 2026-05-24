package com.goc.zkp.range.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.zkp.range.bitdecomposition.ec.ECBindingProof;
import com.goc.zkp.range.bitdecomposition.ec.ECOrProof;
import com.weavechain.curve25519.RistrettoElement;

/**
 * EC counterpart of {@link com.goc.zkp.range.RangeProof}.
 *
 * Holds the per-bit Pedersen commitments, their 0/1 OR-proofs, the
 * resulting Enc_update ciphertext, and the Chaum-Pedersen binding
 * proof that ties the ciphertext to the sender's secret key.
 */
public class ECRangeProof {

    private final RistrettoElement[] bitCommitments;
    private final ECOrProof[]        bitProofs;
    private final ECCiphertext       encryptedValue;
    private final ECBindingProof     bindingProof;
    private final int                bitLength;

    public ECRangeProof(RistrettoElement[] bitCommitments,
                        ECOrProof[]        bitProofs,
                        ECCiphertext       encryptedValue,
                        ECBindingProof     bindingProof,
                        int                bitLength) {
        this.bitCommitments = bitCommitments;
        this.bitProofs      = bitProofs;
        this.encryptedValue = encryptedValue;
        this.bindingProof   = bindingProof;
        this.bitLength      = bitLength;
    }

    public RistrettoElement[] getBitCommitments() { return bitCommitments; }
    public ECOrProof[]        getBitProofs()      { return bitProofs; }
    public ECCiphertext       getEncryptedValue() { return encryptedValue; }
    public ECBindingProof     getBindingProof()   { return bindingProof; }
    public int                getBitLength()      { return bitLength; }
}
