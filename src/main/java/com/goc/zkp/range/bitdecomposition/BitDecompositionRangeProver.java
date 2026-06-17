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
 * Range proof via bit decomposition.
 *
 * Two commitments to the same value v are produced:
 *
 *   ElGamal (decryptable):  c1 = g^a,  c2 = g^v · pk^a   with a = r + H(g^r)
 *   Pedersen (range proof):  C = g^v · h^s               with INDEPENDENT h
 *
 * Each bit gets a Pedersen commitment  commit_i = g^{b_i} · h^{r_i}  and a
 * 0/1 OR-proof; their weighted product Π commit_i^{2^i} = g^v · h^s = C.
 * Because log_g(h) is unknown, the bit commitments are binding, so the
 * OR-proofs genuinely constrain v ∈ [0, 2^k).
 *
 * A value-link proof certifies that C and c2 hide the same v, and a
 * Chaum-Pedersen binding proof authenticates the ciphertext to the sender.
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

        BigInteger v  = witness.value();
        BigInteger pk = witness.publicKey();
        BigInteger x  = witness.secretKey();

        // --- Enc_update ElGamal encryption of v ---
        BigInteger r    = crypto.generateRandomness();
        BigInteger R    = group.pow(group.g, r);
        BigInteger yExp = FiatShamir.hashToZq(group.q, DomainTags.ENC_UPDATE_DERIVE, R);
        BigInteger a    = r.add(yExp).mod(group.q);

        BigInteger c1 = group.pow(group.g, a);
        BigInteger c2 = group.mul(group.pow(group.g, v), group.pow(pk, a)); // g^v · pk^a
        Ciphertext encryptedValue = new Ciphertext(c1, c2);

        // --- Pedersen bit commitments on the INDEPENDENT generator h ---
        BigInteger[] bitRandomness = new BigInteger[bitLength];
        BigInteger[] commitments   = new BigInteger[bitLength];
        OrProof[]    bitProofs      = new OrProof[bitLength];
        BigInteger   s             = BigInteger.ZERO; // s = Σ r_i · 2^i

        for (int i = 0; i < bitLength; i++) {
            int bit = witness.value().testBit(i) ? 1 : 0;
            bitRandomness[i] = crypto.generateRandomness();
            commitments[i]   = pedersenCommit(bit, bitRandomness[i]);
            bitProofs[i]     = proveBitIsZeroOrOne(bit, bitRandomness[i], commitments[i]);
            s = s.add(bitRandomness[i].shiftLeft(i)).mod(group.q);
        }

        BigInteger C = aggregate(commitments); // = g^v · h^s

        // --- Proofs binding everything together ---
        ValueLinkProof linkProof    = proveValueLink(v, a, s, pk, c2, C);
        BindingProof   bindingProof = proveBinding(x, pk, yExp, R, encryptedValue);

        return new RangeProof(commitments, bitProofs, C, encryptedValue,
                linkProof, bindingProof, bitLength);
    }

    // -----------------------------------------------------------------
    // Pedersen commitment on the independent generator h
    // -----------------------------------------------------------------

    private BigInteger pedersenCommit(int bit, BigInteger randomness) {
        BigInteger gPart = (bit == 1) ? group.g : BigInteger.ONE;
        BigInteger hPart = group.pow(group.h, randomness);
        return group.mul(gPart, hPart);
    }

    /**
     * Pedersen-bit OR-proof (Cramer–Damgård–Schoenmakers).
     *
     * Statement: commit = h^r  ∨  commit · g^{-1} = h^r
     *
     * - Real branch (b = actual bit): standard sigma commitment using known r.
     * - Fake branch (1-b): challenge and response chosen at random; the sigma
     *   commitment is back-computed from the verification equation.
     */
    private OrProof proveBitIsZeroOrOne(int bit, BigInteger r, BigInteger commitment) {
        int real = bit;
        int fake = 1 - bit;

        BigInteger target1    = group.mul(commitment, group.inverse(group.g));
        BigInteger fakeTarget = (fake == 0) ? commitment : target1;

        BigInteger[] a = new BigInteger[2];
        BigInteger[] c = new BigInteger[2];
        BigInteger[] z = new BigInteger[2];

        BigInteger w = crypto.generateRandomness();
        a[real] = group.pow(group.h, w);

        c[fake] = crypto.generateRandomness();
        z[fake] = crypto.generateRandomness();
        a[fake] = group.mul(
                group.pow(group.h, z[fake]),
                group.inverse(group.pow(fakeTarget, c[fake]))
        );

        BigInteger total = FiatShamir.hashToZq(
                group.q,
                DomainTags.OR_PROOF_CHALLENGE,
                group.g, group.h, commitment, a[0], a[1]
        );
        c[real] = total.subtract(c[fake]).mod(group.q);
        z[real] = w.add(c[real].multiply(r)).mod(group.q);

        return new OrProof(commitment, a[0], a[1], c[0], c[1], z[0], z[1]);
    }

    /**
     * Value-link proof: c2 = g^v · pk^a  ∧  C = g^v · h^s  share the same v.
     *
     * Commit:    t1 = g^{rv} · pk^{ra},  t2 = g^{rv} · h^{rs}
     * Challenge: e  = H(g, pk, h, c2, C, t1, t2)
     * Response:  zv = rv + e·v,  za = ra + e·a,  zs = rs + e·s
     */
    private ValueLinkProof proveValueLink(BigInteger v, BigInteger a, BigInteger s,
                                          BigInteger pk, BigInteger c2, BigInteger C) {
        BigInteger rv = crypto.generateRandomness();
        BigInteger ra = crypto.generateRandomness();
        BigInteger rs = crypto.generateRandomness();

        BigInteger t1 = group.mul(group.pow(group.g, rv), group.pow(pk, ra));
        BigInteger t2 = group.mul(group.pow(group.g, rv), group.pow(group.h, rs));

        BigInteger e = FiatShamir.hashToZq(
                group.q, DomainTags.VALUE_LINK_CHALLENGE,
                group.g, pk, group.h, c2, C, t1, t2);

        BigInteger zv = rv.add(e.multiply(v)).mod(group.q);
        BigInteger za = ra.add(e.multiply(a)).mod(group.q);
        BigInteger zs = rs.add(e.multiply(s)).mod(group.q);

        return new ValueLinkProof(t1, t2, zv, za, zs);
    }

    /**
     * Chaum-Pedersen NIZK proving g^x = pk ∧ y^x = z, where y = g^{y_exp}
     * and z = pk^{y_exp}. Transcript binds the proof to (R, c1, c2).
     */
    private BindingProof proveBinding(BigInteger x, BigInteger pk,
                                      BigInteger yExp, BigInteger R,
                                      Ciphertext encryptedValue) {
        BigInteger y = group.pow(group.g, yExp);
        BigInteger z = group.pow(pk, yExp);

        BigInteger w  = crypto.generateRandomness();
        BigInteger K1 = group.pow(group.g, w);
        BigInteger K2 = group.pow(y, w);

        BigInteger challenge = FiatShamir.hashToZq(
                group.q,
                DomainTags.BINDING_PROOF_CHALLENGE,
                group.g, pk, y, z, R,
                encryptedValue.c1, encryptedValue.c2,
                K1, K2
        );
        BigInteger s = w.add(challenge.multiply(x)).mod(group.q);

        return new BindingProof(R, K1, K2, s);
    }

    /** Aggregates Π commit_i^{2^i} = g^v · h^s. */
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
