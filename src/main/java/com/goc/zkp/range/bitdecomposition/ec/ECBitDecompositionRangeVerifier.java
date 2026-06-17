package com.goc.zkp.range.bitdecomposition.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.ec.ECFiatShamir;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeVerifier;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * EC counterpart of
 * {@link com.goc.zkp.range.bitdecomposition.BitDecompositionRangeVerifier}.
 *
 * Checks:
 *   1. Proof dimensions match the configured bit length.
 *   2. Each Pedersen commitment (on the independent generator h) opens to
 *      0 or 1 (OR-proof) — sound because log_g(h) is unknown.
 *   3. Aggregated commitment matches C:  Σ commit_i · 2^i == C.
 *   4. Value-link proof: C and the ElGamal c2 carry the same v.
 *   5. Enc_update structure: c1 == R + H(R)·G.
 *   6. Chaum-Pedersen binding proof: pk = x·G ∧ z = x·y.
 */
public class ECBitDecompositionRangeVerifier implements ECRangeVerifier {

    private final ECCryptoGroup group;
    private final int bitLength;

    public ECBitDecompositionRangeVerifier(ECCryptoGroup group, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        this.group = group;
        this.bitLength = bitLength;
    }

    @Override
    public boolean verify(ECRangeProof proof, RistrettoElement publicKey) {
        if (!validateDimensions(proof)) return false;

        RistrettoElement[] commitments = proof.getBitCommitments();
        ECOrProof[]        bitProofs   = proof.getBitProofs();

        for (int i = 0; i < bitLength; i++) {
            if (!commitments[i].equals(bitProofs[i].commitment())) return false;
            if (!verifyBitIsZeroOrOne(bitProofs[i]))               return false;
        }

        if (!verifyAggregation(proof)) return false;
        if (!verifyValueLink(proof, publicKey)) return false;
        return verifyBinding(proof, publicKey);
    }

    private boolean validateDimensions(ECRangeProof proof) {
        return proof.getBitLength() == bitLength
                && proof.getBitCommitments().length == bitLength
                && proof.getBitProofs().length      == bitLength
                && proof.getPedersenCommitment() != null
                && proof.getValueLinkProof()     != null
                && proof.getBindingProof()       != null;
    }

    /** Recomputes Σ commit_i · 2^i and compares it to the claimed C. */
    private boolean verifyAggregation(ECRangeProof proof) {
        RistrettoElement[] commitments = proof.getBitCommitments();
        RistrettoElement   acc         = commitments[0];
        Scalar             weight      = Scalar.ONE.add(Scalar.ONE);   // 2^1
        for (int i = 1; i < bitLength; i++) {
            acc    = acc.add(commitments[i].multiply(weight));
            weight = weight.add(weight);
        }
        return acc.equals(proof.getPedersenCommitment());
    }

    /**
     * Pedersen-bit OR-proof check (base = independent generator h):
     *   c0 + c1 == H(g, h, commit, a0, a1)
     *   z0·h == a0 + c0·commit
     *   z1·h == a1 + c1·(commit − G)
     */
    private boolean verifyBitIsZeroOrOne(ECOrProof proof) {
        RistrettoElement commit  = proof.commitment();
        RistrettoElement target1 = commit.subtract(group.g);

        Scalar total = ECFiatShamir.hashToScalar(
                DomainTags.EC_OR_PROOF_CHALLENGE,
                group.g, group.h, commit, proof.a0(), proof.a1()
        );
        if (!total.equals(proof.c0().add(proof.c1()))) return false;

        RistrettoElement lhs0 = group.h.multiply(proof.z0());
        RistrettoElement rhs0 = proof.a0().add(commit.multiply(proof.c0()));
        if (!lhs0.equals(rhs0)) return false;

        RistrettoElement lhs1 = group.h.multiply(proof.z1());
        RistrettoElement rhs1 = proof.a1().add(target1.multiply(proof.c1()));
        return lhs1.equals(rhs1);
    }

    /**
     * Value-link proof check: C = v·G + s·h and c2 = v·G + a·pk share v.
     *   e = H(g, pk, h, c2, C, t1, t2)
     *   zv·G + za·pk == t1 + e·c2
     *   zv·G + zs·h  == t2 + e·C
     */
    private boolean verifyValueLink(ECRangeProof proof, RistrettoElement publicKey) {
        ECValueLinkProof lp = proof.getValueLinkProof();
        RistrettoElement c2 = proof.getEncryptedValue().c2;
        RistrettoElement C  = proof.getPedersenCommitment();

        Scalar e = ECFiatShamir.hashToScalar(
                DomainTags.EC_VALUE_LINK_CHALLENGE,
                group.g, publicKey, group.h, c2, C, lp.t1(), lp.t2());

        RistrettoElement lhs1 = group.g.multiply(lp.zv()).add(publicKey.multiply(lp.za()));
        RistrettoElement rhs1 = lp.t1().add(c2.multiply(e));
        if (!lhs1.equals(rhs1)) return false;

        RistrettoElement lhs2 = group.g.multiply(lp.zv()).add(group.h.multiply(lp.zs()));
        RistrettoElement rhs2 = lp.t2().add(C.multiply(e));
        return lhs2.equals(rhs2);
    }

    /** Enc_update consistency + Chaum-Pedersen binding proof. */
    private boolean verifyBinding(ECRangeProof proof, RistrettoElement publicKey) {
        ECBindingProof   bp = proof.getBindingProof();
        ECCiphertext     ct = proof.getEncryptedValue();
        RistrettoElement R  = bp.R();

        Scalar           yExp = ECFiatShamir.hashToScalar(DomainTags.EC_ENC_UPDATE_DERIVE, R);
        RistrettoElement y    = group.g.multiply(yExp);
        RistrettoElement z    = publicKey.multiply(yExp);

        if (!R.add(y).equals(ct.c1)) return false;

        Scalar challenge = ECFiatShamir.hashToScalar(
                DomainTags.EC_BINDING_PROOF_CHALLENGE,
                group.g, publicKey, y, z, R,
                ct.c1, ct.c2,
                bp.commitmentK1(), bp.commitmentK2()
        );

        RistrettoElement lhsG = group.g.multiply(bp.responseS());
        RistrettoElement rhsG = bp.commitmentK1().add(publicKey.multiply(challenge));
        if (!lhsG.equals(rhsG)) return false;

        RistrettoElement lhsY = y.multiply(bp.responseS());
        RistrettoElement rhsY = bp.commitmentK2().add(z.multiply(challenge));
        return lhsY.equals(rhsY);
    }
}
