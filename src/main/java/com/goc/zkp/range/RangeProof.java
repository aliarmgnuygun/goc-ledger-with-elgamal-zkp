package com.goc.zkp.range;

import com.goc.core.Ciphertext;
import com.goc.zkp.Proof;
import com.goc.zkp.range.bitdecomposition.BindingProof;
import com.goc.zkp.range.bitdecomposition.OrProof;

import java.math.BigInteger;

/**
 * Bit-decomposition range proof over Enc_update ciphertexts.
 *
 * Holds:
 *   - one Pedersen commitment per bit:  commit_i = g^{b_i} · h^{r_i}
 *   - one OR-proof per bit proving b_i ∈ {0, 1}
 *   - the Enc_update ciphertext  Enc_update(v) = (g^a, g^v · h^a)
 *     where a = r + H(g^r) and c2 = Π commit_i^{2^i}
 *   - a Chaum-Pedersen binding proof tying the ciphertext to the
 *     sender's secret key (proves g^x = h and y^x = z)
 */
public class RangeProof implements Proof {

    private final BigInteger[] bitCommitments;
    private final OrProof[] bitProofs;
    private final Ciphertext encryptedValue;
    private final BindingProof bindingProof;
    private final int bitLength;

    public RangeProof(BigInteger[] bitCommitments,
                      OrProof[] bitProofs,
                      Ciphertext encryptedValue,
                      BindingProof bindingProof,
                      int bitLength) {
        this.bitCommitments = bitCommitments;
        this.bitProofs = bitProofs;
        this.encryptedValue = encryptedValue;
        this.bindingProof = bindingProof;
        this.bitLength = bitLength;
    }

    public BigInteger[] getBitCommitments() { return bitCommitments; }
    public OrProof[] getBitProofs() { return bitProofs; }
    public Ciphertext getEncryptedValue() { return encryptedValue; }
    public BindingProof getBindingProof() { return bindingProof; }
    public int getBitLength() { return bitLength; }
}
