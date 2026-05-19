package com.goc.zkp.equivalence;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;

import java.math.BigInteger;

/**
 * Checks whether two ciphertexts encrypt the same value under a given
 * public key, using only the proof and the public key.
 */
public class CiphertextEquivalenceVerifier {

    private final CryptoGroup group;

    public CiphertextEquivalenceVerifier(CryptoGroup group) {
        this.group = group;
    }

    public boolean verify(CiphertextEquivalenceProof proof,
                          BigInteger publicKey,
                          Ciphertext ctA,
                          Ciphertext ctB) {
        BigInteger c1Diff = group.mul(ctA.c1, group.inverse(ctB.c1));
        BigInteger c2Diff = group.mul(ctA.c2, group.inverse(ctB.c2));

        BigInteger challenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.CIPHERTEXT_EQUIVALENCE_CHALLENGE,
                group.g, publicKey, c1Diff, c2Diff,
                proof.commitmentK1(), proof.commitmentK2()
        );

        // g^s == K1 · h^c
        BigInteger lhsG = group.pow(group.g, proof.responseS());
        BigInteger rhsG = group.mul(proof.commitmentK1(), group.pow(publicKey, challenge));
        if (!lhsG.equals(rhsG)) return false;

        // c1Diff^s == K2 · c2Diff^c
        BigInteger lhsD = group.pow(c1Diff, proof.responseS());
        BigInteger rhsD = group.mul(proof.commitmentK2(), group.pow(c2Diff, challenge));
        return lhsD.equals(rhsD);
    }
}
