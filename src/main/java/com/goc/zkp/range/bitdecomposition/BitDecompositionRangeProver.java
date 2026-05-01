package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeProver;
import com.goc.zkp.range.RangeWitness;
import com.goc.zkp.range.equality.EqualityProof;
import com.goc.zkp.range.equality.EqualityProver;
import com.goc.zkp.range.equality.EqualityWitness;

import java.math.BigInteger;

/**
 * Produces a range proof via bit decomposition.
 * <p>
 * Proves that a value lies in [0, 2^bitLength) without revealing it.
 * Each bit is encrypted individually:
 * - ChaumPedersenProof: proves correctness of the derived key
 * - OrProof:            proves the encrypted bit is 0 or 1
 * <p>
 * All bits are combined with powers-of-two weights to recover
 * an encryption of the original value: Enc(v) = ∏ Enc(bit_i)^(2^i)
 */
public class BitDecompositionRangeProver implements RangeProver {

    private final CryptoGroup group;
    private final Crypto crypto;
    private final int bitLength;
    private final EqualityProver equalityProver;

    public BitDecompositionRangeProver(CryptoGroup group, Crypto crypto, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        this.group = group;
        this.crypto = crypto;
        this.bitLength = bitLength;
        this.equalityProver = new EqualityProver(group, crypto);
    }

    @Override
    public RangeProof prove(RangeWitness witness) {
        validateRange(witness.value());

        Ciphertext[] encryptedBits = new Ciphertext[bitLength];
        OrProof[] bitProofs = new OrProof[bitLength];
        EqualityProof[] keyProofs = new EqualityProof[bitLength];

        for (int i = 0; i < bitLength; i++) {
            int bit = witness.value().testBit(i) ? 1 : 0;
            BigInteger randomness = crypto.generateRandomness();

            // c1 = g^r
            BigInteger c1 = group.pow(group.g, randomness);

            // A unique (y, z) pair is derived from c1 for each bit —
            // prevents the same key from being reused across different bits (replay protection)
            //   y = g^H(c1)
            //   z = y^x
            BigInteger derivedBase = group.pow(group.g,
                    FiatShamir.hashToZq(group.q, DomainTags.BIT_DECOMPOSITION_BASE, c1));
            BigInteger derivedPublicKey = group.pow(derivedBase, witness.secretKey());

            // c2 = h^r · g^bit · z
            BigInteger c2 = group.mul(
                    group.mul(
                            group.pow(witness.publicKey(), randomness),
                            group.pow(group.g, BigInteger.valueOf(bit))
                    ),
                    derivedPublicKey
            );

            Ciphertext ciphertext = new Ciphertext(c1, c2);
            encryptedBits[i] = ciphertext;
            keyProofs[i] = equalityProver.prove(new EqualityWitness(
                    witness.secretKey(), // x
                    group.g,             // g1
                    derivedBase,         // g2 = y
                    witness.publicKey(), // a  = h = g^x
                    derivedPublicKey     // b  = z = y^x
            ));
            bitProofs[i] = proveBitIsZeroOrOne(bit, randomness, ciphertext,
                    witness.publicKey(), derivedPublicKey);
        }

        Ciphertext encryptedValue = aggregateBits(encryptedBits);
        return new RangeProof(encryptedBits, bitProofs, keyProofs, encryptedValue, bitLength);
    }

    /**
     * Proves that the encrypted bit is either 0 or 1, without revealing which.
     * <p>
     * Two branches (bit=0 and bit=1) produce commitments:
     * - Real branch:  standard sigma commitment using the known randomness.
     * - Fake branch:  challenge and response are chosen randomly upfront;
     * the commitment is back-computed from the verification equation.
     * <p>
     * The total challenge is fixed via Fiat-Shamir and split between branches:
     * e_real = totalChallenge - e_fake  (mod q)
     * <p>
     * The verifier checks:
     * e[0] + e[1] == H(...)                    (challenge sum)
     * g^z[i]      == commitment[i] · c1^e[i]   (c1 consistency)
     * h^z[i]      == response[i]  · t[i]^e[i]  (c2 consistency)
     */
    private OrProof proveBitIsZeroOrOne(
            int bit,
            BigInteger randomness,
            Ciphertext ciphertext,
            BigInteger publicKey,
            BigInteger derivedPublicKey
    ) {
        BigInteger c1 = ciphertext.c1;
        BigInteger c2 = ciphertext.c2;
        BigInteger z = derivedPublicKey;

        // Strip z contribution from the ciphertext: c2' = c2 / z
        // c2' now behaves like a standard ElGamal ciphertext.
        BigInteger normalizedC2 = group.mul(c2, group.inverse(z));
        BigInteger normalizedC2IfOne = group.mul(normalizedC2, group.inverse(group.g));

        int realIndex = bit;
        int fakeIndex = 1 - bit;

        // Target ciphertext for the fake branch:
        //   fakeBit=0 → normalizedC2       (act as if bit=0 was encrypted)
        //   fakeBit=1 → normalizedC2IfOne  (act as if bit=1 was encrypted)
        BigInteger fakeTarget = (fakeIndex == 0) ? normalizedC2 : normalizedC2IfOne;

        BigInteger[] commitments = new BigInteger[2];
        BigInteger[] responses = new BigInteger[2];
        BigInteger[] challenges = new BigInteger[2];
        BigInteger[] respZ = new BigInteger[2];

        // Real branch — standard sigma commitment
        BigInteger w = crypto.generateRandomness();
        commitments[realIndex] = group.pow(group.g, w);
        responses[realIndex] = group.pow(publicKey, w);

        // Fake branch — commitment is back-computed from the verification equation:
        //   commitment = g^fakeResp · c1^(-fakeChallenge)
        //   response   = h^fakeResp · fakeTarget^(-fakeChallenge)
        challenges[fakeIndex] = crypto.generateRandomness();
        respZ[fakeIndex] = crypto.generateRandomness();
        commitments[fakeIndex] = group.mul(
                group.pow(group.g, respZ[fakeIndex]),
                group.inverse(group.pow(c1, challenges[fakeIndex]))
        );
        responses[fakeIndex] = group.mul(
                group.pow(publicKey, respZ[fakeIndex]),
                group.inverse(group.pow(fakeTarget, challenges[fakeIndex]))
        );

        // Total challenge is fixed via Fiat-Shamir; real branch takes its share
        BigInteger totalChallenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.OR_PROOF_CHALLENGE,
                group.g, publicKey, c1, c2, z,
                commitments[0], responses[0],
                commitments[1], responses[1]
        );
        challenges[realIndex] = totalChallenge.subtract(challenges[fakeIndex]).mod(group.q);
        respZ[realIndex] = w.add(challenges[realIndex].multiply(randomness)).mod(group.q);

        return new OrProof(
                ciphertext,
                commitments[0], responses[0],
                commitments[1], responses[1],
                challenges[0], challenges[1],
                respZ[0], respZ[1]
        );
    }

    /**
     * Combines bit encryptions with powers-of-two weights:
     * Enc(v) = ∏ Enc(bit_i)^(2^i)
     */
    private Ciphertext aggregateBits(Ciphertext[] encryptedBits) {
        BigInteger c1 = encryptedBits[0].c1;
        BigInteger c2 = encryptedBits[0].c2;
        for (int i = 1; i < bitLength; i++) {
            BigInteger weight = BigInteger.ONE.shiftLeft(i); // 2^i
            c1 = group.mul(c1, group.pow(encryptedBits[i].c1, weight));
            c2 = group.mul(c2, group.pow(encryptedBits[i].c2, weight));
        }
        return new Ciphertext(c1, c2);
    }

    private void validateRange(BigInteger value) {
        if (value.signum() < 0 || value.bitLength() > bitLength) {
            throw new IllegalArgumentException(
                    "value " + value + " does not fit in " + bitLength + " bits"
            );
        }
    }
}