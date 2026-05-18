package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.crypto.DomainTags;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeProver;
import com.goc.zkp.range.RangeWitness;

import java.math.BigInteger;

/**
 * Produces a range proof via bit decomposition over Pedersen commitments.
 *
 * For a value v ∈ [0, 2^k) the prover outputs:
 *   - k Pedersen commitments  commit_i = g^{b_i} · h^{r_i}
 *   - k OR-proofs that each commit_i opens to 0 or 1
 *   - the ElGamal ciphertext  Enc(v) = (g^r, g^v · h^r)
 *
 * Randomness for the lowest bit is forced so that aggregation matches
 * the encryption randomness:
 *   r_0 = r − Σ_{i=1..k-1} r_i · 2^i   (mod q)
 * giving  Π commit_i^{2^i} = g^v · h^r = c2.
 *
 * The prover does NOT need the secret key — only the public key. The
 * owner can later decrypt the encrypted value with their secret key.
 */
public class BitDecompositionRangeProver implements RangeProver {

    private final CryptoGroup group;
    private final Crypto crypto;
    private final int bitLength;

    public BitDecompositionRangeProver(CryptoGroup group, Crypto crypto, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        this.group = group;
        this.crypto = crypto;
        this.bitLength = bitLength;
    }

    @Override
    public RangeProof prove(RangeWitness witness) {
        validateRange(witness.value());

        BigInteger h = witness.publicKey();
        BigInteger r = crypto.generateRandomness();

        BigInteger[] bitRandomness = pickBitRandomness(r);
        BigInteger[] commitments   = new BigInteger[bitLength];
        OrProof[]    bitProofs     = new OrProof[bitLength];

        for (int i = 0; i < bitLength; i++) {
            int bit = witness.value().testBit(i) ? 1 : 0;
            commitments[i] = pedersenCommit(bit, bitRandomness[i], h);
            bitProofs[i]   = proveBitIsZeroOrOne(bit, bitRandomness[i], commitments[i], h);
        }

        Ciphertext encryptedValue = new Ciphertext(
                group.pow(group.g, r),
                aggregate(commitments)
        );
        return new RangeProof(commitments, bitProofs, encryptedValue, bitLength);
    }

    /**
     * Picks r_1 .. r_{k-1} uniformly and forces r_0 so that
     * Σ r_i · 2^i ≡ r  (mod q).
     */
    private BigInteger[] pickBitRandomness(BigInteger r) {
        BigInteger[] bitRandomness = new BigInteger[bitLength];
        BigInteger weightedSum = BigInteger.ZERO;
        for (int i = 1; i < bitLength; i++) {
            bitRandomness[i] = crypto.generateRandomness();
            weightedSum = weightedSum.add(bitRandomness[i].shiftLeft(i)).mod(group.q);
        }
        bitRandomness[0] = r.subtract(weightedSum).mod(group.q);
        return bitRandomness;
    }

    private BigInteger pedersenCommit(int bit, BigInteger randomness, BigInteger h) {
        BigInteger gPart = (bit == 1) ? group.g : BigInteger.ONE;
        BigInteger hPart = group.pow(h, randomness);
        return group.mul(gPart, hPart);
    }

    /**
     * Standard Pedersen-bit OR-proof (Cramer–Damgård–Schoenmakers).
     *
     * Statement: commit = h^r  ∨  commit · g^{-1} = h^r
     *
     * - Real branch (b = actual bit): standard sigma commitment using known r.
     * - Fake branch (1-b): challenge and response chosen at random;
     *                      sigma commitment back-computed from the
     *                      verification equation.
     *
     * The total challenge is bound via Fiat-Shamir and split between
     * branches so c0 + c1 ≡ H(g, h, commit, a0, a1) (mod q).
     */
    private OrProof proveBitIsZeroOrOne(int bit, BigInteger r,
                                        BigInteger commitment, BigInteger h) {
        int real = bit;
        int fake = 1 - bit;

        BigInteger target0 = commitment;
        BigInteger target1 = group.mul(commitment, group.inverse(group.g));
        BigInteger fakeTarget = (fake == 0) ? target0 : target1;

        BigInteger[] a = new BigInteger[2];
        BigInteger[] c = new BigInteger[2];
        BigInteger[] z = new BigInteger[2];

        // Real branch — fresh sigma commitment
        BigInteger w = crypto.generateRandomness();
        a[real] = group.pow(h, w);

        // Fake branch — pick (c_fake, z_fake) at random, back-compute a_fake
        c[fake] = crypto.generateRandomness();
        z[fake] = crypto.generateRandomness();
        a[fake] = group.mul(
                group.pow(h, z[fake]),
                group.inverse(group.pow(fakeTarget, c[fake]))
        );

        // Fiat-Shamir: total challenge fixes the split
        BigInteger total = FiatShamir.hashToZq(
                group.q,
                DomainTags.OR_PROOF_CHALLENGE,
                group.g, h, commitment, a[0], a[1]
        );
        c[real] = total.subtract(c[fake]).mod(group.q);
        z[real] = w.add(c[real].multiply(r)).mod(group.q);

        return new OrProof(commitment, a[0], a[1], c[0], c[1], z[0], z[1]);
    }

    /**
     * Aggregates  Π commit_i^{2^i}  which equals  g^v · h^r  when the
     * randomness was picked so that Σ r_i · 2^i ≡ r (mod q).
     */
    private BigInteger aggregate(BigInteger[] commitments) {
        BigInteger acc = commitments[0];
        for (int i = 1; i < bitLength; i++) {
            BigInteger weight = BigInteger.ONE.shiftLeft(i);
            acc = group.mul(acc, group.pow(commitments[i], weight));
        }
        return acc;
    }

    private void validateRange(BigInteger value) {
        if (value.signum() < 0 || value.bitLength() > bitLength) {
            throw new IllegalArgumentException(
                    "value " + value + " does not fit in " + bitLength + " bits");
        }
    }
}
