package com.goc.core.ec;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

/**
 * EC key pair. The secret key is a Ristretto scalar; the public key is
 * the corresponding Ristretto point sk · G.
 */
public class ECKeyPair {

    public final Scalar secretKey;
    public final RistrettoElement publicKey;

    public ECKeyPair(Scalar secretKey, RistrettoElement publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }
}
