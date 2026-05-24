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
 * <p>
 * Encryption (Enc_update):
 * r       ← random Scalar
 * R       = r · G                   (revealed in the binding proof)
 * y_exp   = H(R)                    (Fiat-Shamir scalar)
 * a       = r + y_exp               (effective randomness)
 * c1      = a · G  (= R + y_exp · G)
 * c2      = v · G + a · H           (recovered via Pedersen aggregation)
 * <p>
 * Bit randomness for the lowest bit is forced so aggregation matches a:
 * r_0 = a − Σ_{i≥1} r_i · 2^i
 * <p>
 * Each bit gets a Pedersen-bit OR-proof; the whole ciphertext is bound
 * to the sender via a Chaum-Pedersen NIZK on (g, h, y, z).
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

        RistrettoElement h = witness.publicKey();
        Scalar x = witness.secretKey();

        // Enc_update randomness derivation
        Scalar r = crypto.generateRandomness();
        RistrettoElement R = group.g.multiply(r);
        Scalar yExp = ECFiatShamir.hashToScalar(DomainTags.EC_ENC_UPDATE_DERIVE, R);
        Scalar a = r.add(yExp);

        Scalar[] bitRandomness = pickBitRandomness(a);
        RistrettoElement[] commitments = new RistrettoElement[bitLength];
        ECOrProof[] bitProofs = new ECOrProof[bitLength];

        for (int i = 0; i < bitLength; i++) {
            int bit = witness.value().testBit(i) ? 1 : 0;
            commitments[i] = pedersenCommit(bit, bitRandomness[i], h);
            bitProofs[i] = proveBitIsZeroOrOne(bit, bitRandomness[i], commitments[i], h);
        }

        ECCiphertext encryptedValue = new ECCiphertext(
                group.g.multiply(a),
                aggregate(commitments)
        );

        ECBindingProof bindingProof = proveBinding(x, h, yExp, R, encryptedValue);

        return new ECRangeProof(commitments, bitProofs, encryptedValue, bindingProof, bitLength);
    }

    // -----------------------------------------------------------------
    // Bit randomness with r_0 forced
    // -----------------------------------------------------------------

    private Scalar[] pickBitRandomness(Scalar a) {
        Scalar[] bitRandomness = new Scalar[bitLength];
        Scalar weightedSum = Scalar.ZERO;
        Scalar weight = Scalar.ONE.add(Scalar.ONE);   // 2^1
        for (int i = 1; i < bitLength; i++) {
            bitRandomness[i] = crypto.generateRandomness();
            weightedSum = weightedSum.add(bitRandomness[i].multiply(weight));
            weight = weight.add(weight); // double for next iteration
        }
        bitRandomness[0] = a.subtract(weightedSum);
        return bitRandomness;
    }

    private RistrettoElement pedersenCommit(int bit, Scalar randomness, RistrettoElement h) {
        RistrettoElement hPart = h.multiply(randomness);
        return (bit == 1) ? group.g.add(hPart) : hPart;
    }

    // -----------------------------------------------------------------
    // Pedersen-bit OR-proof (Cramer–Damgård–Schoenmakers)
    //
    // Statement: commit = r·H  ∨  commit − G = r·H
    //
    // Real branch (b = actual bit): standard sigma commitment using known r.
    // Fake branch (1-b): challenge and response chosen at random; the
    //                    commitment is back-computed from the verification
    //                    equation.
    // -----------------------------------------------------------------

    private ECOrProof proveBitIsZeroOrOne(int bit, Scalar r,
                                          RistrettoElement commitment,
                                          RistrettoElement h) {
        int real = bit;
        int fake = 1 - bit;

        RistrettoElement target0 = commitment;
        RistrettoElement target1 = commitment.subtract(group.g);
        RistrettoElement fakeTarget = (fake == 0) ? target0 : target1;

        RistrettoElement[] a = new RistrettoElement[2];
        Scalar[] c = new Scalar[2];
        Scalar[] z = new Scalar[2];

        // Real branch: a_real = w · H, response later.
        Scalar w = crypto.generateRandomness();
        a[real] = h.multiply(w);

        // Fake branch: pick c_fake, z_fake at random; back-compute a_fake.
        //   a_fake = z_fake · H  −  c_fake · fakeTarget
        c[fake] = crypto.generateRandomness();
        z[fake] = crypto.generateRandomness();
        a[fake] = h.multiply(z[fake]).subtract(fakeTarget.multiply(c[fake]));

        // Fiat-Shamir total challenge.
        Scalar total = ECFiatShamir.hashToScalar(
                DomainTags.EC_OR_PROOF_CHALLENGE,
                group.g, h, commitment, a[0], a[1]
        );
        c[real] = total.subtract(c[fake]);
        z[real] = w.add(c[real].multiply(r));

        return new ECOrProof(commitment, a[0], a[1], c[0], c[1], z[0], z[1]);
    }

    // -----------------------------------------------------------------
    // Chaum-Pedersen binding proof: H = sk·G ∧ z = sk·y
    // -----------------------------------------------------------------

    private ECBindingProof proveBinding(Scalar x,
                                        RistrettoElement h,
                                        Scalar yExp,
                                        RistrettoElement R,
                                        ECCiphertext encryptedValue) {
        RistrettoElement y = group.g.multiply(yExp);
        RistrettoElement z = h.multiply(yExp);  // = y · x in additive form

        Scalar w = crypto.generateRandomness();
        RistrettoElement K1 = group.g.multiply(w);
        RistrettoElement K2 = y.multiply(w);

        Scalar challenge = ECFiatShamir.hashToScalar(
                DomainTags.EC_BINDING_PROOF_CHALLENGE,
                group.g, h, y, z, R,
                encryptedValue.c1, encryptedValue.c2,
                K1, K2
        );
        Scalar s = w.add(challenge.multiply(x));

        return new ECBindingProof(R, K1, K2, s);
    }

    // -----------------------------------------------------------------
    // Aggregation: Σ commit_i · 2^i  =  v · G + a · H  =  c2
    // -----------------------------------------------------------------

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
}
