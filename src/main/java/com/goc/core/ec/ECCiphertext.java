package com.goc.core.ec;

import com.weavechain.curve25519.RistrettoElement;

/**
 * EC ElGamal ciphertext over Ristretto255.
 *
 * c1 = r · G
 * c2 = m · G + r · H     (H = public key)
 *
 * Decryption: c2 − sk · c1 = m · G
 */
public class ECCiphertext {

    public final RistrettoElement c1;
    public final RistrettoElement c2;

    public ECCiphertext(RistrettoElement c1, RistrettoElement c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    /** Homomorphic addition: Enc(a) + Enc(b) = Enc(a + b). */
    public ECCiphertext add(ECCiphertext other) {
        return new ECCiphertext(this.c1.add(other.c1), this.c2.add(other.c2));
    }

    /** Homomorphic subtraction: Enc(a) − Enc(b) = Enc(a − b). */
    public ECCiphertext subtract(ECCiphertext other) {
        return new ECCiphertext(this.c1.subtract(other.c1), this.c2.subtract(other.c2));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ECCiphertext that)) return false;
        return c1.equals(that.c1) && c2.equals(that.c2);
    }

    @Override
    public int hashCode() {
        return 31 * c1.hashCode() + c2.hashCode();
    }
}
