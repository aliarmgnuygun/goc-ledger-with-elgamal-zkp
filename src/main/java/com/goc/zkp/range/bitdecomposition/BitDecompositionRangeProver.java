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
 * Range proof via bit decomposition over Enc_update ciphertexts.
 *
 * Encryption (Enc_update):
 *   r       ← random in Z_q
 *   R       = g^r                  (revealed in the binding proof)
 *   y_exp   = H(R)                 (scalar, via Fiat-Shamir)
 *   a       = r + y_exp  (mod q)   (effective randomness)
 *   c1      = g^a  (= R · g^{y_exp})
 *   c2      = g^v · h^a            (recovered via Pedersen aggregation)
 *
 * Bit randomness for the lowest bit is forced so aggregation matches a:
 *   r_0 = a − Σ_{i≥1} r_i · 2^i  (mod q)
 * giving  Π commit_i^{2^i} = g^v · h^a = c2.
 *
 * For each bit a Pedersen-bit OR-proof shows b_i ∈ {0, 1}.
 *
 * A Chaum-Pedersen binding proof attests that the ciphertext was crafted
 * by the holder of the secret key x, i.e. g^x = h ∧ y^x = z, where
 * y = g^{y_exp} and z = h^{y_exp}.
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
        BigInteger x = witness.secretKey();

        // Enc_update randomness derivation
        BigInteger r     = crypto.generateRandomness();
        BigInteger R     = group.pow(group.g, r);
        BigInteger yExp  = FiatShamir.hashToZq(group.q, DomainTags.ENC_UPDATE_DERIVE, R);
        BigInteger a     = r.add(yExp).mod(group.q);

        BigInteger[] bitRandomness = pickBitRandomness(a);
        BigInteger[] commitments   = new BigInteger[bitLength];
        OrProof[]    bitProofs     = new OrProof[bitLength];

        for (int i = 0; i < bitLength; i++) {
            int bit = witness.value().testBit(i) ? 1 : 0;
            commitments[i] = pedersenCommit(bit, bitRandomness[i], h);
            bitProofs[i]   = proveBitIsZeroOrOne(bit, bitRandomness[i], commitments[i], h);
        }

        Ciphertext encryptedValue = new Ciphertext(
                group.pow(group.g, a),
                aggregate(commitments)
        );

        BindingProof bindingProof = proveBinding(x, h, yExp, R, encryptedValue);

        return new RangeProof(commitments, bitProofs, encryptedValue, bindingProof, bitLength);
    }

    /**
     * Picks r_1 .. r_{k-1} uniformly and forces r_0 so that
     * Σ r_i · 2^i ≡ a (mod q).
     */
    private BigInteger[] pickBitRandomness(BigInteger a) {
        BigInteger[] bitRandomness = new BigInteger[bitLength];
        BigInteger weightedSum = BigInteger.ZERO;
        for (int i = 1; i < bitLength; i++) {
            bitRandomness[i] = crypto.generateRandomness();
            weightedSum = weightedSum.add(bitRandomness[i].shiftLeft(i)).mod(group.q);
        }
        bitRandomness[0] = a.subtract(weightedSum).mod(group.q);
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

        BigInteger w = crypto.generateRandomness();
        a[real] = group.pow(h, w);

        c[fake] = crypto.generateRandomness();
        z[fake] = crypto.generateRandomness();
        a[fake] = group.mul(
                group.pow(h, z[fake]),
                group.inverse(group.pow(fakeTarget, c[fake]))
        );

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
     * Chaum-Pedersen NIZK proving g^x = h ∧ y^x = z, where
     * y = g^{y_exp} and z = h^{y_exp}. Transcript binds the proof to
     * (R, c1, c2) so it cannot be replayed against another ciphertext.
     */
    private BindingProof proveBinding(BigInteger x, BigInteger h,
                                      BigInteger yExp, BigInteger R,
                                      Ciphertext encryptedValue) {
        BigInteger y = group.pow(group.g, yExp);
        BigInteger z = group.pow(h, yExp); // = y^x

        BigInteger w  = crypto.generateRandomness();
        BigInteger K1 = group.pow(group.g, w);
        BigInteger K2 = group.pow(y, w);

        BigInteger challenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.BINDING_PROOF_CHALLENGE,
                group.g, h, y, z, R,
                encryptedValue.c1, encryptedValue.c2,
                K1, K2
        );
        BigInteger s = w.add(challenge.multiply(x)).mod(group.q);

        return new BindingProof(R, K1, K2, s);
    }

    /**
     * Aggregates  Π commit_i^{2^i}  which equals  g^v · h^a  when the
     * randomness was picked so that Σ r_i · 2^i ≡ a (mod q).
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
