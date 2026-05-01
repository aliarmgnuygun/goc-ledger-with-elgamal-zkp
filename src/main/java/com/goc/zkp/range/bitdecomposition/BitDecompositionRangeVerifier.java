package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeVerifier;
import com.goc.zkp.range.equality.EqualityProof;
import com.goc.zkp.range.equality.EqualityVerifier;

import java.math.BigInteger;

/**
 * Verifies a bit-decomposition range proof.
 * <p>
 * Ensures that:
 * 1. Proof dimensions match the expected bit length.
 * 2. The aggregated ciphertext matches the provided encrypted value.
 * 3. Each bit's derived key is valid (Chaum-Pedersen).
 * 4. Each encrypted bit is strictly 0 or 1 (OrProof).
 */
public class BitDecompositionRangeVerifier implements RangeVerifier {

    private final CryptoGroup group;
    private final BigInteger publicKey;
    private final int bitLength;
    private final EqualityVerifier equalityVerifier;

    // The verifier does not need randomness (Crypto) — only the public key.
    public BitDecompositionRangeVerifier(CryptoGroup group, BigInteger publicKey, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        this.group = group;
        this.publicKey = publicKey;
        this.bitLength = bitLength;
        this.equalityVerifier = new EqualityVerifier(group);
    }

    @Override
    public boolean verify(RangeProof proof) {
        if (!validateDimensions(proof)) return false;
        if (!verifyAggregation(proof)) return false;

        Ciphertext[] encryptedBits = proof.getEncryptedBits();
        OrProof[] bitProofs = proof.getBitProofs();
        EqualityProof[] keyProofs = proof.getKeyProofs();

        for (int i = 0; i < bitLength; i++) {
            BigInteger c1 = encryptedBits[i].c1;

            BigInteger derivedBase = group.pow(group.g,
                    FiatShamir.hashToZq(group.q, DomainTags.BIT_DECOMPOSITION_BASE, c1));

            BigInteger derivedPublicKey = keyProofs[i].b();

            if (!equalityVerifier.verify(keyProofs[i], group.g, c1, derivedBase, derivedPublicKey)) return false;
            if (!verifyBitIsZeroOrOne(bitProofs[i], encryptedBits[i], derivedPublicKey)) return false;
        }

        return true;
    }

    // -------------------------------------------------------------------------
    // Dimension check
    // -------------------------------------------------------------------------

    private boolean validateDimensions(RangeProof proof) {
        return proof.getBitLength() == bitLength
                && proof.getEncryptedBits().length == bitLength
                && proof.getBitProofs().length == bitLength
                && proof.getKeyProofs().length == bitLength;
    }

    // -------------------------------------------------------------------------
    // Aggregation check
    // -------------------------------------------------------------------------

    /**
     * Recomputes Enc(v) = ∏ Enc(bit_i)^(2^i) and compares it
     * against the encryptedValue claimed in the proof.
     */
    private boolean verifyAggregation(RangeProof proof) {
        Ciphertext[] encryptedBits = proof.getEncryptedBits();

        BigInteger c1 = encryptedBits[0].c1;
        BigInteger c2 = encryptedBits[0].c2;

        for (int i = 1; i < bitLength; i++) {
            BigInteger weight = BigInteger.ONE.shiftLeft(i); // 2^i
            c1 = group.mul(c1, group.pow(encryptedBits[i].c1, weight));
            c2 = group.mul(c2, group.pow(encryptedBits[i].c2, weight));
        }

        Ciphertext encryptedValue = proof.getEncryptedValue();
        return c1.equals(encryptedValue.c1) && c2.equals(encryptedValue.c2);
    }

    // -------------------------------------------------------------------------
    // OrProof check (bit ∈ {0, 1})
    // -------------------------------------------------------------------------

    /**
     * Verifies that the encrypted bit is 0 or 1.
     * <p>
     * totalChallenge = H(g, h, c1, c2, z, a0, d0, a1, d1)
     * e0 + e1 == totalChallenge  (mod q)
     * <p>
     * Branch 0:
     * g^z0 == a0 · c1^e0
     * h^z0 == d0 · (c2')^e0
     * <p>
     * Branch 1:
     * g^z1 == a1 · c1^e1
     * h^z1 == d1 · (c2' / g)^e1
     */
    private boolean verifyBitIsZeroOrOne(
            OrProof proof,
            Ciphertext ciphertext,
            BigInteger derivedPublicKey
    ) {
        BigInteger c1 = ciphertext.c1;
        BigInteger c2 = ciphertext.c2;

        BigInteger normalizedC2 = group.mul(c2, group.inverse(derivedPublicKey));
        BigInteger normalizedC2IfOne = group.mul(normalizedC2, group.inverse(group.g));

        // Challenge sum check
        BigInteger totalChallenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.OR_PROOF_CHALLENGE,
                group.g, publicKey, c1, c2, derivedPublicKey,
                proof.commitmentA0(), proof.commitmentD0(),
                proof.commitmentA1(), proof.commitmentD1()
        );

        BigInteger challengeSum = proof.challengeE0().add(proof.challengeE1()).mod(group.q);
        if (!totalChallenge.equals(challengeSum)) return false;

        // Branch 0: g^z0 == a0 · c1^e0
        if (!group.pow(group.g, proof.responseZ0()).equals(
                group.mul(proof.commitmentA0(), group.pow(c1, proof.challengeE0())))) return false;

        // Branch 0: h^z0 == d0 · (c2')^e0
        if (!group.pow(publicKey, proof.responseZ0()).equals(
                group.mul(proof.commitmentD0(), group.pow(normalizedC2, proof.challengeE0())))) return false;

        // Branch 1: g^z1 == a1 · c1^e1
        if (!group.pow(group.g, proof.responseZ1()).equals(
                group.mul(proof.commitmentA1(), group.pow(c1, proof.challengeE1())))) return false;

        // Branch 1: h^z1 == d1 · (c2' / g)^e1
        return group.pow(publicKey, proof.responseZ1()).equals(
                group.mul(proof.commitmentD1(), group.pow(normalizedC2IfOne, proof.challengeE1())));
    }
}