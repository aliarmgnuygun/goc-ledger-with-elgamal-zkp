package com.goc.zkp.range.equality;

import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.Prover;

import java.math.BigInteger;

/**
 * Produces an EqualityProof.
 *
 * Proves knowledge of x such that:
 * a = g1^x  and  b = g2^x
 *
 * Commit:    k1 = g1^w,  k2 = g2^w
 * Challenge: c  = H(g1, g2, a, b, k1, k2)
 * Response:  z  = w + c * x  (mod q)
 */
public class EqualityProver implements Prover<EqualityWitness, EqualityProof> {

    private final CryptoGroup group;
    private final Crypto crypto;

    public EqualityProver(CryptoGroup group, Crypto crypto) {
        this.group = group;
        this.crypto = crypto;
    }

    @Override
    public EqualityProof prove(EqualityWitness witness) {
        BigInteger w = crypto.generateRandomness();

        BigInteger commitmentK1 = group.pow(witness.g1(), w); // g1^w
        BigInteger commitmentK2 = group.pow(witness.g2(), w); // g2^w

        BigInteger challenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.EQUALITY_PROOF_CHALLENGE,
                witness.g1(), witness.g2(),
                witness.a(), witness.b(),
                commitmentK1, commitmentK2
        );

        BigInteger responseZ = w.add(challenge.multiply(witness.x())).mod(group.q);

        return new EqualityProof(
                witness.g1(), witness.g2(),
                witness.a(), witness.b(),
                commitmentK1, commitmentK2,
                responseZ
        );
    }
}
