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
 * <p>
 * Checks:
 * 1. Proof dimensions match the configured bit length.
 * 2. Each Pedersen commitment opens to 0 or 1 (OR-proof).
 * 3. Aggregated commitment matches c2:  Σ commit_i · 2^i == encryptedValue.c2.
 * 4. Enc_update structure: c1 == R + H(R) · G.
 * 5. Chaum-Pedersen binding proof: H = sk · G ∧ z = sk · y.
 */
public class ECBitDecompositionRangeVerifier implements ECRangeVerifier {

    private final ECCryptoGroup group;
    private final int bitLength;

    public ECBitDecompositionRangeVerifier(ECCryptoGroup group, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        if (bitLength > 63) throw new IllegalArgumentException("bitLength must fit in a long (<= 63)");
        this.group = group;
        this.bitLength = bitLength;
    }

    @Override
    public boolean verify(ECRangeProof proof, RistrettoElement publicKey) {
        if (!validateDimensions(proof)) return false;

        RistrettoElement[] commitments = proof.getBitCommitments();
        ECOrProof[] bitProofs = proof.getBitProofs();

        for (int i = 0; i < bitLength; i++) {
            if (!commitments[i].equals(bitProofs[i].commitment())) return false;
            if (!verifyBitIsZeroOrOne(bitProofs[i], publicKey)) return false;
        }

        if (!verifyAggregation(proof)) return false;
        return verifyBinding(proof, publicKey);
    }

    private boolean validateDimensions(ECRangeProof proof) {
        return proof.getBitLength() == bitLength
                && proof.getBitCommitments().length == bitLength
                && proof.getBitProofs().length == bitLength
                && proof.getBindingProof() != null;
    }

    /**
     * Recomputes  Σ commit_i · 2^i  and compares it to encryptedValue.c2.
     */
    private boolean verifyAggregation(ECRangeProof proof) {
        RistrettoElement[] commitments = proof.getBitCommitments();
        RistrettoElement acc = commitments[0];
        Scalar weight = Scalar.ONE.add(Scalar.ONE);   // 2^1
        for (int i = 1; i < bitLength; i++) {
            acc = acc.add(commitments[i].multiply(weight));
            weight = weight.add(weight);
        }
        return acc.equals(proof.getEncryptedValue().c2);
    }

    /**
     * Pedersen-bit OR-proof check:
     * c0 + c1 == H(g, h, commit, a0, a1)
     * z0 · H == a0 + c0 · commit
     * z1 · H == a1 + c1 · (commit − G)
     */
    private boolean verifyBitIsZeroOrOne(ECOrProof proof, RistrettoElement publicKey) {
        RistrettoElement commit = proof.commitment();
        RistrettoElement target1 = commit.subtract(group.g);

        Scalar total = ECFiatShamir.hashToScalar(
                DomainTags.EC_OR_PROOF_CHALLENGE,
                group.g, publicKey, commit, proof.a0(), proof.a1()
        );
        if (!total.equals(proof.c0().add(proof.c1()))) return false;

        RistrettoElement lhs0 = publicKey.multiply(proof.z0());
        RistrettoElement rhs0 = proof.a0().add(commit.multiply(proof.c0()));
        if (!lhs0.equals(rhs0)) return false;

        RistrettoElement lhs1 = publicKey.multiply(proof.z1());
        RistrettoElement rhs1 = proof.a1().add(target1.multiply(proof.c1()));
        return lhs1.equals(rhs1);
    }

    /**
     * Enc_update consistency  +  Chaum-Pedersen binding proof.
     * y   = H(R) · G
     * z   = H(R) · H
     * c1 == R + y
     * c   = H(... g, h, y, z, R, c1, c2, K1, K2)
     * s·G == K1 + c·H
     * s·y == K2 + c·z
     */
    private boolean verifyBinding(ECRangeProof proof, RistrettoElement publicKey) {
        ECBindingProof bp = proof.getBindingProof();
        ECCiphertext ct = proof.getEncryptedValue();
        RistrettoElement R = bp.R();

        Scalar yExp = ECFiatShamir.hashToScalar(DomainTags.EC_ENC_UPDATE_DERIVE, R);
        RistrettoElement y = group.g.multiply(yExp);
        RistrettoElement z = publicKey.multiply(yExp);

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
