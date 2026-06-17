package com.goc.zkp.range.bitdecomposition.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.crypto.DomainTags;
import com.goc.crypto.ec.ECCrypto;
import com.goc.crypto.ec.ECFiatShamir;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeProver;
import com.goc.zkp.range.ec.ECRangeWitness;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import java.math.BigInteger;

/**
 * EC counterpart of
 * {@link com.goc.zkp.range.bitdecomposition.BitDecompositionRangeProver}.
 *
 * Two commitments to the same value v are produced on Ristretto255:
 *
 *   ElGamal (decryptable):  c1 = a·G,  c2 = v·G + a·pk   with a = r + H(r·G)
 *   Pedersen (range proof):  C = v·G + s·H               with INDEPENDENT h
 *
 * Each bit gets  commit_i = b_i·G + r_i·h  and a 0/1 OR-proof; their
 * weighted sum Σ commit_i·2^i = v·G + s·H = C. Because log_g(h) is
 * unknown, the bit commitments are binding, so the OR-proofs genuinely
 * constrain v ∈ [0, 2^k).
 *
 * A value-link proof certifies C and c2 carry the same v; a Chaum-Pedersen
 * binding proof authenticates the ciphertext to the sender.
 */
public class ECBitDecompositionRangeProver implements ECRangeProver {

    private final ECCryptoGroup group;
    private final ECCrypto crypto;
    private final int bitLength;

    public ECBitDecompositionRangeProver(ECCryptoGroup group, ECCrypto crypto, int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        this.group = group;
        this.crypto = crypto;
        this.bitLength = bitLength;
    }

    @Override
    public ECRangeProof prove(ECRangeWitness witness) {
        validateRange(witness.value());

        Scalar           v  = scalarFromBigInteger(witness.value());
        RistrettoElement pk = witness.publicKey();
        Scalar           x  = witness.secretKey();

        // --- Enc_update ElGamal encryption of v ---
        Scalar           r    = crypto.generateRandomness();
        RistrettoElement R    = group.g.multiply(r);
        Scalar           yExp = ECFiatShamir.hashToScalar(DomainTags.EC_ENC_UPDATE_DERIVE, R);
        Scalar           a    = r.add(yExp);

        RistrettoElement c1 = group.g.multiply(a);
        RistrettoElement c2 = group.g.multiply(v).add(pk.multiply(a)); // v·G + a·pk
        ECCiphertext encryptedValue = new ECCiphertext(c1, c2);

        // --- Pedersen bit commitments on the INDEPENDENT generator h ---
        RistrettoElement[] commitments = new RistrettoElement[bitLength];
        ECOrProof[]        bitProofs   = new ECOrProof[bitLength];
        Scalar             s           = Scalar.ZERO; // s = Σ r_i · 2^i
        Scalar             weight      = Scalar.ONE;  // 2^0, doubled each step

        for (int i = 0; i < bitLength; i++) {
            int    bit = witness.value().testBit(i) ? 1 : 0;
            Scalar ri  = crypto.generateRandomness();
            commitments[i] = pedersenCommit(bit, ri);
            bitProofs[i]   = proveBitIsZeroOrOne(bit, ri, commitments[i]);
            s      = s.add(ri.multiply(weight));
            weight = weight.add(weight);
        }

        RistrettoElement C = aggregate(commitments); // = v·G + s·H

        ECValueLinkProof linkProof    = proveValueLink(v, a, s, pk, c2, C);
        ECBindingProof   bindingProof = proveBinding(x, pk, yExp, R, encryptedValue);

        return new ECRangeProof(commitments, bitProofs, C, encryptedValue,
                linkProof, bindingProof, bitLength);
    }

    // -----------------------------------------------------------------
    // Pedersen commitment on the independent generator h
    // -----------------------------------------------------------------

    private RistrettoElement pedersenCommit(int bit, Scalar randomness) {
        RistrettoElement hPart = group.h.multiply(randomness);
        return (bit == 1) ? group.g.add(hPart) : hPart;
    }

    /**
     * Pedersen-bit OR-proof (Cramer–Damgård–Schoenmakers).
     * Statement: commit = r·h  ∨  commit − G = r·h
     */
    private ECOrProof proveBitIsZeroOrOne(int bit, Scalar r, RistrettoElement commitment) {
        int real = bit;
        int fake = 1 - bit;

        RistrettoElement target1    = commitment.subtract(group.g);
        RistrettoElement fakeTarget = (fake == 0) ? commitment : target1;

        RistrettoElement[] a = new RistrettoElement[2];
        Scalar[]           c = new Scalar[2];
        Scalar[]           z = new Scalar[2];

        Scalar w = crypto.generateRandomness();
        a[real] = group.h.multiply(w);

        c[fake] = crypto.generateRandomness();
        z[fake] = crypto.generateRandomness();
        a[fake] = group.h.multiply(z[fake]).subtract(fakeTarget.multiply(c[fake]));

        Scalar total = ECFiatShamir.hashToScalar(
                DomainTags.EC_OR_PROOF_CHALLENGE,
                group.g, group.h, commitment, a[0], a[1]
        );
        c[real] = total.subtract(c[fake]);
        z[real] = w.add(c[real].multiply(r));

        return new ECOrProof(commitment, a[0], a[1], c[0], c[1], z[0], z[1]);
    }

    /**
     * Value-link proof: c2 = v·G + a·pk  ∧  C = v·G + s·h  share the same v.
     */
    private ECValueLinkProof proveValueLink(Scalar v, Scalar a, Scalar s,
                                            RistrettoElement pk,
                                            RistrettoElement c2, RistrettoElement C) {
        Scalar rv = crypto.generateRandomness();
        Scalar ra = crypto.generateRandomness();
        Scalar rs = crypto.generateRandomness();

        RistrettoElement t1 = group.g.multiply(rv).add(pk.multiply(ra));
        RistrettoElement t2 = group.g.multiply(rv).add(group.h.multiply(rs));

        Scalar e = ECFiatShamir.hashToScalar(
                DomainTags.EC_VALUE_LINK_CHALLENGE,
                group.g, pk, group.h, c2, C, t1, t2);

        Scalar zv = rv.add(e.multiply(v));
        Scalar za = ra.add(e.multiply(a));
        Scalar zs = rs.add(e.multiply(s));

        return new ECValueLinkProof(t1, t2, zv, za, zs);
    }

    /** Chaum-Pedersen binding proof: pk = x·G ∧ z = x·y. */
    private ECBindingProof proveBinding(Scalar x, RistrettoElement pk,
                                        Scalar yExp, RistrettoElement R,
                                        ECCiphertext encryptedValue) {
        RistrettoElement y = group.g.multiply(yExp);
        RistrettoElement z = pk.multiply(yExp);

        Scalar           w  = crypto.generateRandomness();
        RistrettoElement K1 = group.g.multiply(w);
        RistrettoElement K2 = y.multiply(w);

        Scalar challenge = ECFiatShamir.hashToScalar(
                DomainTags.EC_BINDING_PROOF_CHALLENGE,
                group.g, pk, y, z, R,
                encryptedValue.c1, encryptedValue.c2,
                K1, K2
        );
        Scalar s = w.add(challenge.multiply(x));

        return new ECBindingProof(R, K1, K2, s);
    }

    /** Aggregates Σ commit_i · 2^i = v·G + s·H. */
    private RistrettoElement aggregate(RistrettoElement[] commitments) {
        RistrettoElement acc = commitments[0];
        Scalar weight = Scalar.ONE.add(Scalar.ONE);   // 2^1
        for (int i = 1; i < bitLength; i++) {
            acc = acc.add(commitments[i].multiply(weight));
            weight = weight.add(weight);
        }
        return acc;
    }

    private void validateRange(BigInteger value) {
        if (value.signum() < 0 || value.bitLength() > bitLength) {
            throw new IllegalArgumentException(
                    "value " + value + " does not fit in " + bitLength + " bits");
        }
    }

    /** Converts a non-negative BigInteger (&lt; 2^252) into a Ristretto Scalar. */
    private static Scalar scalarFromBigInteger(BigInteger value) {
        byte[] be = value.toByteArray();          // big-endian, possibly with sign byte
        byte[] le = new byte[32];
        int n = be.length;
        for (int i = 0; i < n && i < 32; i++) {
            le[i] = be[n - 1 - i];                 // reverse into little-endian
        }
        return Scalar.fromBytesModOrder(le);
    }
}
