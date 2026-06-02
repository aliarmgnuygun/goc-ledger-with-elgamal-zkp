package com.goc.zkp.range.bulletproof;

import com.weavechain.zk.bulletproofs.BulletProofGenerators;
import com.weavechain.zk.bulletproofs.BulletProofs;
import com.weavechain.zk.bulletproofs.PedersenCommitment;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.NumberInRangeParams;

/**
 * Verifies Bulletproof range proofs produced by
 * {@link BulletproofRangeProver}.
 *
 * The verifier holds its own copies of the gadget registry, the
 * Pedersen commitment generators, and the Bulletproof generator table.
 * In real deployments these would come from a public set-up that both
 * sides agree on; here we re-derive them from the same defaults so the
 * benchmark mirrors the EC/DL implementations.
 */
public class BulletproofRangeVerifier {

    private static final int GENERATOR_CAPACITY = 128;
    private static final int GENERATOR_SHARES   = 1;

    private final BulletProofs          bulletProofs;
    private final PedersenCommitment    pedersenCommitment;
    private final BulletProofGenerators generators;
    private final int                   bitLength;

    public BulletproofRangeVerifier(int bitLength) {
        if (bitLength <= 0) throw new IllegalArgumentException("bitLength must be positive");
        if (bitLength > 63) throw new IllegalArgumentException("Bulletproof gadget upper bound is 63 bits");
        this.bitLength = bitLength;
        this.bulletProofs = new BulletProofs();
        Gadgets.registerGadgets(bulletProofs);
        try {
            this.pedersenCommitment = PedersenCommitment.getDefault();
            this.generators         = new BulletProofGenerators(GENERATOR_CAPACITY, GENERATOR_SHARES);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialise Bulletproof generators", e);
        }
    }

    public boolean verify(BulletproofRangeProof proof) {
        if (proof.getBitLength() != bitLength) return false;

        long max = (bitLength == 63) ? Long.MAX_VALUE : (1L << bitLength);
        NumberInRangeParams params = new NumberInRangeParams(0L, max, bitLength);

        try {
            return bulletProofs.verify(
                    Gadgets.number_in_range,
                    params,
                    proof.getProof(),
                    pedersenCommitment,
                    generators
            );
        } catch (Exception e) {
            // weavechain's verify may surface I/O or constraint failures as
            // exceptions on invalid proofs; treat them as rejection.
            return false;
        }
    }
}
