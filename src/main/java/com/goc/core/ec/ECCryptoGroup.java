package com.goc.core.ec;

import com.weavechain.curve25519.Constants;
import com.weavechain.curve25519.RistrettoElement;

/**
 * Wrapper around the Ristretto255 prime-order group.
 *
 * Mirrors {@link com.goc.core.CryptoGroup} for symmetry across DL and EC
 * implementations, exposing the base generator. Group arithmetic is
 * performed directly on {@link RistrettoElement} via its native
 * additive API (add / subtract / negate / multiply).
 */
public class ECCryptoGroup {

    /** Canonical Ristretto generator (analogous to "g" in the DL group). */
    public final RistrettoElement g = Constants.RISTRETTO_GENERATOR;

    /** Group order ℓ — kept as a public reminder; Scalar arithmetic reduces mod ℓ automatically. */
    public final java.math.BigInteger order = new java.math.BigInteger(
            "7237005577332262213973186563042994240857116359379907606001950938285454250989");
}
