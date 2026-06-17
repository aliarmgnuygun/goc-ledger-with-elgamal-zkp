package com.goc.zkp.range.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.zkp.range.bitdecomposition.ec.ECBindingProof;
import com.goc.zkp.range.bitdecomposition.ec.ECOrProof;
import com.goc.zkp.range.bitdecomposition.ec.ECValueLinkProof;
import com.weavechain.curve25519.RistrettoElement;

/**
 * EC counterpart of {@link com.goc.zkp.range.RangeProof}.
 *
 * Holds:
 *   - per-bit Pedersen commitments on the INDEPENDENT generator h
 *   - their 0/1 OR-proofs
 *   - the aggregated Pedersen commitment  C = v·G + s·H
 *   - the Enc_update ElGamal ciphertext (c1, c2) the ledger stores
 *   - a value-link proof certifying C and c2 carry the same v
 *   - a Chaum-Pedersen binding proof tying the ciphertext to the sender
 */
public class ECRangeProof {

    private final RistrettoElement[] bitCommitments;
    private final ECOrProof[]        bitProofs;
    private final RistrettoElement   pedersenCommitment; // C = v·G + s·H
    private final ECCiphertext       encryptedValue;     // ElGamal (c1, c2)
    private final ECValueLinkProof   valueLinkProof;     // ties C to c2
    private final ECBindingProof     bindingProof;
    private final int                bitLength;

    public ECRangeProof(RistrettoElement[] bitCommitments,
                        ECOrProof[]        bitProofs,
                        RistrettoElement   pedersenCommitment,
                        ECCiphertext       encryptedValue,
                        ECValueLinkProof   valueLinkProof,
                        ECBindingProof     bindingProof,
                        int                bitLength) {
        this.bitCommitments     = bitCommitments;
        this.bitProofs          = bitProofs;
        this.pedersenCommitment = pedersenCommitment;
        this.encryptedValue     = encryptedValue;
        this.valueLinkProof     = valueLinkProof;
        this.bindingProof       = bindingProof;
        this.bitLength          = bitLength;
    }

    public RistrettoElement[] getBitCommitments()     { return bitCommitments; }
    public ECOrProof[]        getBitProofs()          { return bitProofs; }
    public RistrettoElement   getPedersenCommitment() { return pedersenCommitment; }
    public ECCiphertext       getEncryptedValue()     { return encryptedValue; }
    public ECValueLinkProof   getValueLinkProof()     { return valueLinkProof; }
    public ECBindingProof     getBindingProof()       { return bindingProof; }
    public int                getBitLength()          { return bitLength; }
}
