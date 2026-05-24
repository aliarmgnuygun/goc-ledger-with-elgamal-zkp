package com.goc.zkp.range.ec;

import com.weavechain.curve25519.RistrettoElement;

/**
 * EC counterpart of {@link com.goc.zkp.range.RangeVerifier}.
 * The public key is supplied per call so a single verifier instance
 * can serve every account.
 */
public interface ECRangeVerifier {
    boolean verify(ECRangeProof proof, RistrettoElement publicKey);
}
