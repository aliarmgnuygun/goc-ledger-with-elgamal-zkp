package com.goc.zkp.range.bulletproof;

/**
 * Inputs the sender provides to build a Bulletproof range proof.
 *
 * Bulletproofs commit to the value via a Pedersen commitment whose
 * blinding factor is generated internally and bundled inside the proof;
 * the caller does not need to track randomness or supply a key pair.
 */
public record BulletproofRangeWitness(long value) {}
