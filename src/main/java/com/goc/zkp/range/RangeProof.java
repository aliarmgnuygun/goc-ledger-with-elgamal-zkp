package com.goc.zkp.range;

import com.goc.core.Ciphertext;
import com.goc.zkp.Proof;
import com.goc.zkp.range.bitdecomposition.BindingProof;
import com.goc.zkp.range.bitdecomposition.OrProof;
import com.goc.zkp.range.bitdecomposition.ValueLinkProof;

import java.math.BigInteger;

/**
 * Bit-decomposition range proof.
 *
 * Holds:
 *   - one Pedersen commitment per bit:  commit_i = g^{b_i} · h^{r_i}
 *     (h is an INDEPENDENT generator with unknown log_g(h), so the
 *     commitments are binding and the range proof is sound)
 *   - one OR-proof per bit proving b_i ∈ {0, 1}
 *   - the aggregated Pedersen commitment  C = Π commit_i^{2^i} = g^v · h^s
 *   - the Enc_update ElGamal ciphertext  (c1, c2) = (g^a, g^v · pk^a)
 *     that the ledger stores and the owner can decrypt
 *   - a value-link proof certifying C and c2 carry the same v
 *   - a Chaum-Pedersen binding proof tying the ciphertext to the sender
 */
public class RangeProof implements Proof {

    private final BigInteger[] bitCommitments;
    private final OrProof[] bitProofs;
    private final BigInteger pedersenCommitment;   // C = g^v · h^s
    private final Ciphertext encryptedValue;       // ElGamal (c1, c2)
    private final ValueLinkProof valueLinkProof;   // ties C to c2
    private final BindingProof bindingProof;
    private final int bitLength;

    public RangeProof(BigInteger[] bitCommitments,
                      OrProof[] bitProofs,
                      BigInteger pedersenCommitment,
                      Ciphertext encryptedValue,
                      ValueLinkProof valueLinkProof,
                      BindingProof bindingProof,
                      int bitLength) {
        this.bitCommitments     = bitCommitments;
        this.bitProofs          = bitProofs;
        this.pedersenCommitment = pedersenCommitment;
        this.encryptedValue     = encryptedValue;
        this.valueLinkProof     = valueLinkProof;
        this.bindingProof       = bindingProof;
        this.bitLength          = bitLength;
    }

    public BigInteger[]   getBitCommitments()     { return bitCommitments; }
    public OrProof[]      getBitProofs()          { return bitProofs; }
    public BigInteger     getPedersenCommitment() { return pedersenCommitment; }
    public Ciphertext     getEncryptedValue()     { return encryptedValue; }
    public ValueLinkProof getValueLinkProof()     { return valueLinkProof; }
    public BindingProof   getBindingProof()       { return bindingProof; }
    public int            getBitLength()          { return bitLength; }
}
