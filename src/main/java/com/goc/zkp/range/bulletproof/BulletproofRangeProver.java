package com.goc.zkp.range.bulletproof;

import com.weavechain.ec.RScalar;
import com.weavechain.ec.Scalar;
import com.weavechain.zk.bulletproofs.BulletProofGenerators;
import com.weavechain.zk.bulletproofs.BulletProofs;
import com.weavechain.zk.bulletproofs.PedersenCommitment;
import com.weavechain.zk.bulletproofs.Proof;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.NumberInRangeParams;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Produces Bulletproof range proofs by delegating to weavechain's
 * pure-Java port of dalek-cryptography.
 * <p>
 * The underlying gadget is {@code number_in_range}, which proves that
 * the committed value lies in [0, 2^bitLength) — exactly what we need
 * to mirror our bit-decomposition range proofs.
 */
public class BulletproofRangeProver {

    /**
     * Default generator capacity used by the weavechain example.
     */
    private static final int GENERATOR_CAPACITY = 128;
    private static final int GENERATOR_SHARES = 1;

    private final BulletProofs bulletProofs;
    private final PedersenCommitment pedersenCommitment;
    private final BulletProofGenerators generators;
    private final SecureRandom random = new SecureRandom();
    private final int bitLength;

    public BulletproofRangeProver(int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        if (bitLength > 63) throw new IllegalArgumentException("Bulletproof gadget upper bound is 63 bits");
        this.bitLength = bitLength;
        this.bulletProofs = new BulletProofs();
        Gadgets.registerGadgets(bulletProofs);
        try {
            this.pedersenCommitment = PedersenCommitment.getDefault();
            this.generators = new BulletProofGenerators(GENERATOR_CAPACITY, GENERATOR_SHARES);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialise Bulletproof generators", e);
        }
    }

    public BulletproofRangeProof prove(BulletproofRangeWitness witness) {
        long value = witness.value();
        long max = (bitLength == 63) ? Long.MAX_VALUE : (1L << bitLength);
        if (value < 0 || value >= max) {
            throw new IllegalArgumentException(
                    "value " + value + " does not fit in " + bitLength + " bits");
        }

        NumberInRangeParams params = new NumberInRangeParams(0L, max, bitLength);
        Scalar blinding = randomScalar();

        Proof proof = bulletProofs.generate(
                Gadgets.number_in_range,
                value,
                params,
                blinding,
                pedersenCommitment,
                generators
        );
        return new BulletproofRangeProof(proof, bitLength);
    }

    private Scalar randomScalar() {
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        return new RScalar(com.weavechain.curve25519.Scalar.fromBytesModOrderWide(bytes));
    }

    /**
     * Public accessors so the verifier can reuse the same generator/commitment material.
     */
    public PedersenCommitment pedersenCommitment() {
        return pedersenCommitment;
    }

    public BulletProofGenerators generators() {
        return generators;
    }

    public int bitLength() {
        return bitLength;
    }

    /**
     * Convenience: returns the max value (exclusive) provable at the configured bit length.
     */
    public BigInteger maxExclusive() {
        return BigInteger.ONE.shiftLeft(bitLength);
    }
}
