package com.goc.zkp.equivalence.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.ec.ECFiatShamir;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * Checks whether two EC ciphertexts encrypt the same value under a
 * given public key, using only the proof and the public key.
 */
public class ECCiphertextEquivalenceVerifier {

    private final ECCryptoGroup group;

    public ECCiphertextEquivalenceVerifier(ECCryptoGroup group) {
        this.group = group;
    }

    public boolean verify(ECCiphertextEquivalenceProof proof,
                          RistrettoElement publicKey,
                          ECCiphertext ctA,
                          ECCiphertext ctB) {
        RistrettoElement c1Diff = ctA.c1.subtract(ctB.c1);
        RistrettoElement c2Diff = ctA.c2.subtract(ctB.c2);

        Scalar challenge = ECFiatShamir.hashToScalar(
                DomainTags.EC_CIPHERTEXT_EQUIVALENCE_CHALLENGE,
                group.g, publicKey, c1Diff, c2Diff,
                proof.commitmentK1(), proof.commitmentK2()
        );

        // s · G == K1 + challenge · publicKey
        RistrettoElement lhsG = group.g.multiply(proof.responseS());
        RistrettoElement rhsG = proof.commitmentK1().add(publicKey.multiply(challenge));
        if (!lhsG.equals(rhsG)) return false;

        // s · c1Diff == K2 + challenge · c2Diff
        RistrettoElement lhsD = c1Diff.multiply(proof.responseS());
        RistrettoElement rhsD = proof.commitmentK2().add(c2Diff.multiply(challenge));
        return lhsD.equals(rhsD);
    }
}
