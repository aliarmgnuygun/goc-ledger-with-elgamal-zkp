package com.goc.ledger;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeVerifier;

public class Ledger {

    private final CryptoGroup group;
    private final Ciphertext[][] matrix;
    private final RangeVerifier verifier;

    public Ledger(CryptoGroup group, int size, RangeVerifier verifier) {
        this.group = group;
        this.matrix = new Ciphertext[size][size];
        this.verifier = verifier;
    }

    public boolean submitTransaction(
            int sender,
            int receiver,
            Ciphertext amount,
            RangeProof proof) {

        if (!verifier.verify(proof)) {
            return false;
        }

        if (!amount.equals(proof.getEncryptedValue())) {
            return false;
        }
        
        if (matrix[sender][receiver] == null) {
            matrix[sender][receiver] = amount;
        } else {
            matrix[sender][receiver] = matrix[sender][receiver]
                    .multiply(amount, group);
        }

        return true;
    }

    public Ciphertext getEntry(int i, int j) {
        return matrix[i][j];
    }
}
