package com.goc.zkp.equivalence.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.ec.ECCrypto;
import com.goc.crypto.ec.ECFiatShamir;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * Builds a proof that two EC ciphertexts hide the same value.
 * <p>
 * Used by the sender to show the ledger that her freshly encrypted
 * post-transaction balance matches the one the ledger would compute
 * homomorphically. Only the sender's private key is needed.
 */
public class ECCiphertextEquivalenceProver {

    private final ECCryptoGroup group;
    private final ECCrypto crypto;

    public ECCiphertextEquivalenceProver(ECCryptoGroup group, ECCrypto crypto) {
        this.group = group;
        this.crypto = crypto;
    }

    public ECCiphertextEquivalenceProof prove(Scalar secretKey,
                                              RistrettoElement publicKey,
                                              ECCiphertext ctA,
                                              ECCiphertext ctB) {
        RistrettoElement c1Diff = ctA.c1.subtract(ctB.c1);
        RistrettoElement c2Diff = ctA.c2.subtract(ctB.c2);

        Scalar w = crypto.generateRandomness();
        RistrettoElement K1 = group.g.multiply(w);
        RistrettoElement K2 = c1Diff.multiply(w);

        Scalar challenge = ECFiatShamir.hashToScalar(
                DomainTags.EC_CIPHERTEXT_EQUIVALENCE_CHALLENGE,
                group.g, publicKey, c1Diff, c2Diff, K1, K2
        );
        Scalar s = w.add(challenge.multiply(secretKey));

        return new ECCiphertextEquivalenceProof(K1, K2, s);
    }
}
