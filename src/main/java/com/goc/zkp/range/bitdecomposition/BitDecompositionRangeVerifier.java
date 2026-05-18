package com.goc.zkp.range.bitdecomposition;

import com.goc.core.CryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeVerifier;

import java.math.BigInteger;

/**
 * Verifies a Pedersen-based bit-decomposition range proof.
 *
 * Checks:
 *   1. Proof dimensions match the configured bit length.
 *   2. Each commitment opens to 0 or 1 (OR-proof).
 *   3. Aggregated commitment matches the c2 component of the
 *      encrypted value: Π commit_i^{2^i} == encryptedValue.c2.
 *
 * The verifier never decrypts the encrypted value; it only checks that
 * c2 is well-formed as g^v · h^r with v ∈ [0, 2^k).
 */
public class BitDecompositionRangeVerifier implements RangeVerifier {

    private final CryptoGroup group;
    private final BigInteger publicKey;
    private final int bitLength;

    public BitDecompositionRangeVerifier(CryptoGroup group, BigInteger publicKey, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        this.group = group;
        this.publicKey = publicKey;
        this.bitLength = bitLength;
    }

    @Override
    public boolean verify(RangeProof proof) {
        if (!validateDimensions(proof)) return false;

        BigInteger[] commitments = proof.getBitCommitments();
        OrProof[] bitProofs = proof.getBitProofs();

        for (int i = 0; i < bitLength; i++) {
            if (!commitments[i].equals(bitProofs[i].commitment())) return false;
            if (!verifyBitIsZeroOrOne(bitProofs[i])) return false;
        }

        return verifyAggregation(proof);
    }

    private boolean validateDimensions(RangeProof proof) {
        return proof.getBitLength() == bitLength
                && proof.getBitCommitments().length == bitLength
                && proof.getBitProofs().length == bitLength;
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
    private boolean verifyBitIsZeroOrOne(OrProof proof) {
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
}
