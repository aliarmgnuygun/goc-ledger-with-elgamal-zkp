package com.goc.zkp.equivalence;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;

import java.math.BigInteger;

/**
 * Builds a proof that two ciphertexts hide the same value.
 *
 * Used by the sender to show the ledger that her freshly encrypted
 * post-transaction balance matches the one the ledger would compute
 * homomorphically. Only the sender's private key is needed — no
 * knowledge of the underlying randomness or balance value.
 */
public class CiphertextEquivalenceProver {

    private final CryptoGroup group;
    private final Crypto crypto;

    public CiphertextEquivalenceProver(CryptoGroup group, Crypto crypto) {
        this.group = group;
        this.crypto = crypto;
    }

    public CiphertextEquivalenceProof prove(BigInteger secretKey,
                                            BigInteger publicKey,
                                            Ciphertext ctA,
                                            Ciphertext ctB) {
        BigInteger c1Diff = group.mul(ctA.c1, group.inverse(ctB.c1));
        BigInteger c2Diff = group.mul(ctA.c2, group.inverse(ctB.c2));

        BigInteger w  = crypto.generateRandomness();
        BigInteger K1 = group.pow(group.g, w);
        BigInteger K2 = group.pow(c1Diff, w);

        BigInteger challenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.CIPHERTEXT_EQUIVALENCE_CHALLENGE,
                group.g, publicKey, c1Diff, c2Diff, K1, K2
        );
        BigInteger s = w.add(challenge.multiply(secretKey)).mod(group.q);

        return new CiphertextEquivalenceProof(K1, K2, s);
    }
}
