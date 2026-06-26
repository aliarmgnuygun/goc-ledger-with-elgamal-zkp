package com.goc.demo;

import com.goc.zkp.range.bulletproof.BulletproofRangeProof;
import com.goc.zkp.range.bulletproof.BulletproofRangeProver;
import com.goc.zkp.range.bulletproof.BulletproofRangeVerifier;
import com.goc.zkp.range.bulletproof.BulletproofRangeWitness;

import java.util.List;

/**
 * Re-runs each {@code BulletproofRangeProverTest} case so the demo can show
 * that the Bulletproofs range proof is exercised too — at the range-proof
 * level (a value is / isn't in range), not the ledger level. Bulletproofs is
 * not wired into the transfer flow (it lacks a ciphertext-equivalence proof),
 * so these are correctness checks on the proof itself.
 *
 * Each method returns whether the proof ended up ACCEPTED (produced and
 * verified true) and appends a human-readable trace to {@code log}.
 */
public class BpScenarios {

    private static final int BIT_LENGTH = 32;
    private static final long MAX_IN_RANGE = (1L << BIT_LENGTH) - 1; // 2^32 - 1
    private static final long FIRST_OUT_OF_RANGE = 1L << BIT_LENGTH;  // 2^32

    public boolean run(String id, List<String> log) {
        return switch (id) {
            case "VALID"        -> verifies(42L, log);
            case "SMALL"        -> verifies(1L, log);
            case "MAX"          -> verifies(MAX_IN_RANGE, log);
            case "NEGATIVE"     -> rejectedAtProving(-1L, log);
            case "OUT_OF_RANGE" -> rejectedAtProving(FIRST_OUT_OF_RANGE, log);
            case "BIT_MISMATCH" -> bitMismatch(log);
            case "TAMPERED"     -> tampered(log);
            default -> { log.add("Unknown scenario: " + id); yield false; }
        };
    }

    private boolean verifies(long value, List<String> log) {
        var prover   = new BulletproofRangeProver(BIT_LENGTH);
        var verifier = new BulletproofRangeVerifier(BIT_LENGTH);
        log.add("Step 1: Completeness — build an " + BIT_LENGTH + "-bit Bulletproof for the in-range value " + value + ".");
        BulletproofRangeProof proof = prover.prove(new BulletproofRangeWitness(value));
        log.add("Step 2: The verifier checks that " + value + " lies inside [0, 2^" + BIT_LENGTH + ").");
        boolean ok = verifier.verify(proof);
        log.add(ok ? "Result: VERIFIED ✓ — a valid in-range value is accepted."
                   : "Result: REJECTED ✗ — unexpected.");
        return ok;
    }

    private boolean rejectedAtProving(long value, List<String> log) {
        var prover = new BulletproofRangeProver(BIT_LENGTH);
        log.add("Step 1: Input bound — try to build a proof for the out-of-range value " + value + ".");
        try {
            prover.prove(new BulletproofRangeWitness(value));
            log.add("Result: VERIFIED — unexpected! An out-of-range value should not be provable.");
            return true; // proof produced (unexpected) → counts as "accepted"
        } catch (IllegalArgumentException e) {
            log.add("Result: REJECTED ✗ — the prover refuses: a value outside [0, 2^" + BIT_LENGTH + ") has no valid proof (" + e.getMessage() + ").");
            return false; // correctly rejected before any proof exists
        }
    }

    private boolean tampered(List<String> log) {
        var prover   = new BulletproofRangeProver(BIT_LENGTH);
        var verifier = new BulletproofRangeVerifier(BIT_LENGTH);
        log.add("Step 1: Soundness — build a valid " + BIT_LENGTH + "-bit Bulletproof for the value 42.");
        BulletproofRangeProof proof = prover.prove(new BulletproofRangeWitness(42L));
        try {
            byte[] bytes = proof.getProof().serialize();
            log.add("Step 2: Tamper — flip a single byte in the serialized proof (" + bytes.length + " bytes).");
            bytes[bytes.length / 2] ^= 0x01;
            com.weavechain.zk.bulletproofs.Proof inner =
                    com.weavechain.zk.bulletproofs.Proof.deserialize(bytes);
            log.add("Step 3: The verifier checks the tampered proof.");
            boolean ok = verifier.verify(new BulletproofRangeProof(inner, BIT_LENGTH));
            log.add(ok ? "Result: VERIFIED — unexpected!"
                       : "Result: REJECTED ✗ — even a single flipped byte breaks the proof.");
            return ok;
        } catch (Exception e) {
            log.add("Step 3: The tampered bytes cannot even be parsed back into a valid proof.");
            log.add("Result: REJECTED ✗ — the tampered proof is invalid.");
            return false;
        }
    }

    private boolean bitMismatch(List<String> log) {
        var prover        = new BulletproofRangeProver(BIT_LENGTH);
        var wrongVerifier = new BulletproofRangeVerifier(16);
        log.add("Step 1: Parameter binding — build a proof with a " + BIT_LENGTH + "-bit prover.");
        BulletproofRangeProof proof = prover.prove(new BulletproofRangeWitness(5L));
        log.add("Step 2: Check it with a 16-bit verifier (mismatched parameters).");
        boolean ok = wrongVerifier.verify(proof);
        log.add(ok ? "Result: VERIFIED — unexpected!"
                   : "Result: REJECTED ✗ — the proof is bound to its parameters; a different bit-length rejects it.");
        return ok;
    }
}
