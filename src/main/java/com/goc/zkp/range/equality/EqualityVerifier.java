package com.goc.zkp.range.equality;

import com.goc.core.CryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.Verifier;

import java.math.BigInteger;

/**
 * Verifies an EqualityProof.
 *
 * Checks:
 * c  = H(g1, g2, a, b, k1, k2)
 * g1^z == k1 * a^c
 * g2^z == k2 * b^c
 */
public class EqualityVerifier implements Verifier<EqualityProof> {

    private final CryptoGroup group;

    public EqualityVerifier(CryptoGroup group) {
        this.group = group;
    }

    /**
     * Interface implementation.
     * Uses the internal values of the proof for verification.
     */
    @Override
    public boolean verify(EqualityProof proof) {
        return verify(proof, proof.g1(), proof.g2(), proof.a(), proof.b());
    }

    /**
     * Strong Binding Verification.
     * Validates the proof against externally provided values to ensure context consistency.
     */
    public boolean verify(EqualityProof proof, BigInteger g1, BigInteger g2, BigInteger a, BigInteger b) {
        if (!proof.g1().equals(g1) || !proof.g2().equals(g2) ||
                !proof.a().equals(a) || !proof.b().equals(b)) {
            return false;
        }

        BigInteger challenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.EQUALITY_PROOF_CHALLENGE,
                g1, g2, a, b,
                proof.commitmentK1(), proof.commitmentK2()
        );

        // g1^z == k1 * a^c
        BigInteger lhs1 = group.pow(g1, proof.responseZ());
        BigInteger rhs1 = group.mul(proof.commitmentK1(), group.pow(a, challenge));
        if (!lhs1.equals(rhs1)) return false;

        // g2^z == k2 * b^c
        BigInteger lhs2 = group.pow(g2, proof.responseZ());
        BigInteger rhs2 = group.mul(proof.commitmentK2(), group.pow(b, challenge));
        return lhs2.equals(rhs2);
    }
}
