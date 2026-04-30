package com.goc.zkp.range.bitdecomposition;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.crypto.FiatShamir;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeProver;
import com.goc.zkp.range.RangeWitness;

import java.math.BigInteger;

public class BitDecompositionRangeProver implements RangeProver {

    private final CryptoGroup group;
    private final Crypto crypto;
    private final int bitLength;

    public BitDecompositionRangeProver(CryptoGroup group, Crypto crypto, int bitLength) {
        if (bitLength <= 0) {
            throw new IllegalArgumentException("bitLength must be positive");
        }
        this.group = group;
        this.crypto = crypto;
        this.bitLength = bitLength;
    }

    @Override
    public RangeProof prove(RangeWitness witness) {
        BigInteger value = witness.value();
        BigInteger publicKey = witness.publicKey();

        if (value.signum() < 0 || value.bitLength() > bitLength) {
            throw new IllegalArgumentException(
                    "value " + value + " does not fit in " + bitLength + " bits"
            );
        }

        Ciphertext[] encryptedBits = new Ciphertext[bitLength];
        OrProof[] bitProofs = new OrProof[bitLength];

        for (int i = 0; i < bitLength; i++) {
            int bit = value.testBit(i) ? 1 : 0;
            BigInteger randomness = crypto.generateRandomness();

            BigInteger c1 = group.pow(group.g, randomness);
            BigInteger c2 = group.mul(
                    group.pow(publicKey, randomness),
                    group.pow(group.g, BigInteger.valueOf(bit))
            );

            encryptedBits[i] = new Ciphertext(c1, c2);
            bitProofs[i] = proveOrProof(bit,randomness,encryptedBits[i],publicKey);
        }

        BigInteger aggregatedC1 = encryptedBits[0].c1;
        BigInteger aggregatedC2 = encryptedBits[0].c2;

        for (int i = 1; i < bitLength; i++) {
            BigInteger weight = BigInteger.ONE.shiftLeft(i);
            aggregatedC1 = group.mul(aggregatedC1, group.pow(encryptedBits[i].c1, weight));
            aggregatedC2 = group.mul(aggregatedC2, group.pow(encryptedBits[i].c2, weight));
        }

        Ciphertext encryptedValue = new Ciphertext(aggregatedC1, aggregatedC2);
        return new RangeProof(encryptedBits, bitProofs, encryptedValue, bitLength);
    }

    private OrProof proveOrProof(int bit, BigInteger randomness,
                                 Ciphertext encryptedBit, BigInteger publicKey) {
        BigInteger g  = group.g;
        BigInteger h  = publicKey;
        BigInteger c1 = encryptedBit.c1;
        BigInteger c2 = encryptedBit.c2;

        BigInteger encryptedIfZero = c2;
        BigInteger encryptedIfOne  = group.mul(c2, group.inverse(g));

        BigInteger a0, d0, a1, d1;
        BigInteger e0, e1;
        BigInteger z0, z1;
        if (bit == 0) {
            // Gerçek branch: bit=0
            BigInteger w = crypto.generateRandomness();
            a0 = group.pow(g, w); // g^w
            d0 = group.pow(h, w); // h^w

            // Simüle edilmiş branch: bit=1
            e1 = crypto.generateRandomness();
            z1 = crypto.generateRandomness();
            a1 = group.mul(group.pow(g, z1), group.inverse(group.pow(c1, e1)));
            d1 = group.mul(group.pow(h, z1), group.inverse(group.pow(encryptedIfOne, e1)));

            // e0 + e1 = H(g, h, c1, c2, a0, d0, a1, d1)
            BigInteger totalChallenge = FiatShamir.hashToZq(group.q, g, h, c1, c2, a0, d0, a1, d1);
            e0 = totalChallenge.subtract(e1).mod(group.q);
            z0 = w.add(e0.multiply(randomness)).mod(group.q);

        } else {
            // Gerçek branch: bit=1
            BigInteger w = crypto.generateRandomness();
            a1 = group.pow(g, w);
            d1 = group.pow(h, w);

            // Simüle edilmiş branch: bit=0
            e0 = crypto.generateRandomness();
            z0 = crypto.generateRandomness();
            a0 = group.mul(group.pow(g, z0), group.inverse(group.pow(c1, e0)));
            d0 = group.mul(group.pow(h, z0), group.inverse(group.pow(encryptedIfZero, e0)));

            // e0 + e1 = H(g, h, c1, c2, a0, d0, a1, d1)
            BigInteger totalChallenge = FiatShamir.hashToZq(group.q, g, h, c1, c2, a0, d0, a1, d1);
            e1 = totalChallenge.subtract(e0).mod(group.q);
            z1 = w.add(e1.multiply(randomness)).mod(group.q);
        }

        return new OrProof(encryptedBit, a0, d0, a1, d1, e0, e1, z0, z1);
    }
}