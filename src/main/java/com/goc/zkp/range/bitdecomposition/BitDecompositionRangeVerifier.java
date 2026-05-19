package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeVerifier;

import java.math.BigInteger;

/**
 * Verifies a Pedersen-based bit-decomposition range proof over an
 * Enc_update ciphertext.
 *
 * The public key is supplied at verification time so the ledger can
 * verify each transaction against the sender's own key.
 *
 * Checks:
 *   1. Proof dimensions match the configured bit length.
 *   2. Each Pedersen commitment opens to 0 or 1 (OR-proof).
 *   3. Aggregated commitment matches c2 of the encrypted value:
 *      Π commit_i^{2^i} == encryptedValue.c2.
 *   4. Enc_update structure: c1 = R · g^{H(R)}.
 *   5. Chaum-Pedersen binding proof: g^x = h ∧ y^x = z,
 *      where y = g^{H(R)}, z = h^{H(R)}.
 */
public class BitDecompositionRangeVerifier implements RangeVerifier {

    private final CryptoGroup group;
    private final int bitLength;

    public BitDecompositionRangeVerifier(CryptoGroup group, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        this.group = group;
        this.bitLength = bitLength;
    }

    @Override
    public boolean verify(RangeProof proof, BigInteger publicKey) {
        if (!validateDimensions(proof)) return false;

        BigInteger[] commitments = proof.getBitCommitments();
        OrProof[] bitProofs = proof.getBitProofs();

        for (int i = 0; i < bitLength; i++) {
            if (!commitments[i].equals(bitProofs[i].commitment())) return false;
            if (!verifyBitIsZeroOrOne(bitProofs[i], publicKey)) return false;
        }

        if (!verifyAggregation(proof)) return false;
        return verifyBinding(proof, publicKey);
    }

    private boolean validateDimensions(RangeProof proof) {
        return proof.getBitLength() == bitLength
                && proof.getBitCommitments().length == bitLength
                && proof.getBitProofs().length == bitLength
                && proof.getBindingProof() != null;
    }

    /**
     * Recomputes  Π commit_i^{2^i}  and compares it to encryptedValue.c2.
     */
    private boolean verifyAggregation(RangeProof proof) {
        BigInteger[] commitments = proof.getBitCommitments();
        BigInteger acc = commitments[0];
        for (int i = 1; i < bitLength; i++) {
            BigInteger weight = BigInteger.ONE.shiftLeft(i);
            acc = group.mul(acc, group.pow(commitments[i], weight));
        }
        return acc.equals(proof.getEncryptedValue().c2);
    }

    /**
     * Checks the Pedersen-bit OR-proof.
     *
     *   c0 + c1 == H(g, h, commit, a0, a1)        (mod q)
     *   h^z0 == a0 · commit^c0                    (branch 0)
     *   h^z1 == a1 · (commit · g^{-1})^c1         (branch 1)
     */
    private boolean verifyBitIsZeroOrOne(OrProof proof, BigInteger publicKey) {
        BigInteger commit  = proof.commitment();
        BigInteger target1 = group.mul(commit, group.inverse(group.g));

        BigInteger total = FiatShamir.hashToZq(
                group.q,
                DomainTags.OR_PROOF_CHALLENGE,
                group.g, publicKey, commit, proof.a0(), proof.a1()
        );
        if (!total.equals(proof.c0().add(proof.c1()).mod(group.q))) return false;

        BigInteger lhs0 = group.pow(publicKey, proof.z0());
        BigInteger rhs0 = group.mul(proof.a0(), group.pow(commit, proof.c0()));
        if (!lhs0.equals(rhs0)) return false;

        BigInteger lhs1 = group.pow(publicKey, proof.z1());
        BigInteger rhs1 = group.mul(proof.a1(), group.pow(target1, proof.c1()));
        return lhs1.equals(rhs1);
    }

    /**
     * Checks Enc_update consistency and the Chaum-Pedersen binding proof.
     *
     *   y      = g^{H(R)}
     *   z      = h^{H(R)}         (publicly recomputable; binds to (h, R))
     *   c1     == R · y           (ciphertext consistent with R)
     *   c      = H(... g, h, y, z, R, c1, c2, K1, K2)
     *   g^s    == K1 · h^c
     *   y^s    == K2 · z^c
     */
    private boolean verifyBinding(RangeProof proof, BigInteger publicKey) {
        BindingProof bp = proof.getBindingProof();
        Ciphertext ct = proof.getEncryptedValue();
        BigInteger R = bp.R();

        BigInteger yExp = FiatShamir.hashToZq(group.q, DomainTags.ENC_UPDATE_DERIVE, R);
        BigInteger y = group.pow(group.g, yExp);
        BigInteger z = group.pow(publicKey, yExp);

        if (!group.mul(R, y).equals(ct.c1)) return false;

        BigInteger challenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.BINDING_PROOF_CHALLENGE,
                group.g, publicKey, y, z, R,
                ct.c1, ct.c2,
                bp.commitmentK1(), bp.commitmentK2()
        );

        BigInteger lhsG = group.pow(group.g, bp.responseS());
        BigInteger rhsG = group.mul(bp.commitmentK1(), group.pow(publicKey, challenge));
        if (!lhsG.equals(rhsG)) return false;

        BigInteger lhsY = group.pow(y, bp.responseS());
        BigInteger rhsY = group.mul(bp.commitmentK2(), group.pow(z, challenge));
        return lhsY.equals(rhsY);
    }
}
