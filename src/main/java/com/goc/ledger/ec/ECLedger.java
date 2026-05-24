package com.goc.ledger.ec;

import com.goc.core.ec.ECCiphertext;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.zkp.equivalence.ec.ECCiphertextEquivalenceProof;
import com.goc.zkp.equivalence.ec.ECCiphertextEquivalenceVerifier;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeVerifier;
import com.weavechain.curve25519.RistrettoElement;

/**
 * EC counterpart of {@link com.goc.ledger.Ledger}.
 *
 * Privacy-preserving GOC-Ledger on Ristretto255: stores encrypted
 * balances and accepts transactions only when the sender proves both
 * the transferred amount and her remaining balance are non-negative
 * — without revealing either value.
 *
 * Each account is registered with its own public key, and all proofs
 * are verified against the sender's registered key so a third party
 * cannot submit transactions on someone else's behalf.
 */
public class ECLedger {

    private final ECCryptoGroup group;
    private final int size;
    private final ECCiphertext[][] matrix;
    private final ECCiphertext[] initialBalance;
    private final RistrettoElement[] accountPublicKeys;
    private final ECRangeVerifier rangeVerifier;
    private final ECCiphertextEquivalenceVerifier equivalenceVerifier;

    public ECLedger(ECCryptoGroup group, int size, ECRangeVerifier rangeVerifier) {
        this.group = group;
        this.size = size;
        this.matrix = new ECCiphertext[size][size];
        this.initialBalance = new ECCiphertext[size];
        this.accountPublicKeys = new RistrettoElement[size];
        this.rangeVerifier = rangeVerifier;
        this.equivalenceVerifier = new ECCiphertextEquivalenceVerifier(group);
    }

    /**
     * Registers an account with its public key. Required before the
     * account can send or receive transactions.
     */
    public void registerAccount(int account, RistrettoElement publicKey) {
        accountPublicKeys[account] = publicKey;
    }

    /**
     * Seeds an account with an initial encrypted balance (e.g. minted tokens).
     * Subsequent mints to the same account accumulate homomorphically.
     */
    public void mint(int account, ECCiphertext amount) {
        if (initialBalance[account] == null) {
            initialBalance[account] = amount;
        } else {
            initialBalance[account] = initialBalance[account].add(amount);
        }
    }

    /**
     * Computes the account's current encrypted balance homomorphically:
     * balance = initialBalance + Σ inflows − Σ outflows.
     * Returns {@code null} if the account has neither initial credit
     * nor any inflows/outflows recorded.
     */
    public ECCiphertext computeBalance(int account) {
        ECCiphertext result = initialBalance[account];

        for (int j = 0; j < size; j++) {
            ECCiphertext inflow = matrix[j][account];
            if (inflow != null) {
                result = (result == null) ? inflow : result.add(inflow);
            }
        }
        for (int j = 0; j < size; j++) {
            ECCiphertext outflow = matrix[account][j];
            if (outflow != null) {
                result = (result == null) ? null : result.subtract(outflow);
            }
        }
        return result;
    }

    public boolean submitTransaction(
            int sender,
            int receiver,
            ECCiphertext amount,
            ECRangeProof amountProof,
            ECCiphertext newSenderBalance,
            ECRangeProof newBalanceProof,
            ECCiphertextEquivalenceProof equivalenceProof
    ) {
        // 0. Sender must be a registered account.
        RistrettoElement senderPublicKey = accountPublicKeys[sender];
        if (senderPublicKey == null) return false;

        // 1. Both range proofs must validate against the sender's key.
        if (!rangeVerifier.verify(amountProof, senderPublicKey)) return false;
        if (!amount.equals(amountProof.getEncryptedValue())) return false;

        if (!rangeVerifier.verify(newBalanceProof, senderPublicKey)) return false;
        if (!newSenderBalance.equals(newBalanceProof.getEncryptedValue())) return false;

        // 2. The submitted newSenderBalance must encrypt the same value as
        //    (currentBalance − amount) — i.e. the sender actually has enough.
        ECCiphertext current = computeBalance(sender);
        if (current == null) return false; // no funds at all

        ECCiphertext expectedNewBalance = current.subtract(amount);
        if (!equivalenceVerifier.verify(equivalenceProof,
                senderPublicKey, expectedNewBalance, newSenderBalance)) {
            return false;
        }

        // 3. Apply the matrix update.
        matrix[sender][receiver] = (matrix[sender][receiver] == null)
                ? amount
                : matrix[sender][receiver].add(amount);

        return true;
    }

    public ECCiphertext getEntry(int i, int j) {
        return matrix[i][j];
    }

    public ECCiphertext getInitialBalance(int account) {
        return initialBalance[account];
    }

    public RistrettoElement getAccountPublicKey(int account) {
        return accountPublicKeys[account];
    }
}
