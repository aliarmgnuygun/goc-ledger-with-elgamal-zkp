package com.goc.ledger;

import com.goc.core.Ciphertext;
import com.goc.core.CryptoGroup;
import com.goc.zkp.equivalence.CiphertextEquivalenceProof;
import com.goc.zkp.equivalence.CiphertextEquivalenceVerifier;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeVerifier;

import java.math.BigInteger;

/**
 * Privacy-preserving GOC-Ledger that stores encrypted balances and
 * accepts transactions only when the sender proves both the transferred
 * amount and her remaining balance are non-negative — without revealing
 * either value.
 *
 * Each account is registered with its own public key, and all proofs
 * are verified against the sender's key so a third party cannot submit
 * transactions on someone else's behalf.
 */
public class Ledger {

    private final CryptoGroup group;
    private final int size;
    private final Ciphertext[][] matrix;
    private final Ciphertext[] initialBalance;
    private final BigInteger[] accountPublicKeys;
    private final RangeVerifier rangeVerifier;
    private final CiphertextEquivalenceVerifier equivalenceVerifier;

    public Ledger(CryptoGroup group, int size, RangeVerifier rangeVerifier) {
        this.group = group;
        this.size = size;
        this.matrix = new Ciphertext[size][size];
        this.initialBalance = new Ciphertext[size];
        this.accountPublicKeys = new BigInteger[size];
        this.rangeVerifier = rangeVerifier;
        this.equivalenceVerifier = new CiphertextEquivalenceVerifier(group);
    }

    /**
     * Registers an account with its public key. Required before the
     * account can send or receive transactions.
     */
    public void registerAccount(int account, BigInteger publicKey) {
        accountPublicKeys[account] = publicKey;
    }

    /**
     * Seeds an account with an initial encrypted balance (e.g. minted tokens).
     * Subsequent mints to the same account accumulate homomorphically.
     */
    public void mint(int account, Ciphertext amount) {
        if (initialBalance[account] == null) {
            initialBalance[account] = amount;
        } else {
            initialBalance[account] = initialBalance[account].multiply(amount, group);
        }
    }

    /**
     * Computes the sender's current encrypted balance homomorphically.
     * Returns {@code null} if the account has neither initial credit nor
     * any inflows/outflows recorded.
     */
    public Ciphertext computeBalance(int account) {
        Ciphertext result = initialBalance[account];

        for (int j = 0; j < size; j++) {
            Ciphertext inflow = matrix[j][account];
            if (inflow != null) {
                result = (result == null) ? inflow : result.multiply(inflow, group);
            }
        }
        for (int j = 0; j < size; j++) {
            Ciphertext outflow = matrix[account][j];
            if (outflow != null) {
                result = (result == null) ? null : subtract(result, outflow);
            }
        }
        return result;
    }

    public boolean submitTransaction(
            int sender,
            int receiver,
            Ciphertext amount,
            RangeProof amountProof,
            Ciphertext newSenderBalance,
            RangeProof newBalanceProof,
            CiphertextEquivalenceProof equivalenceProof
    ) {
        // 0. Sender must be a registered account.
        BigInteger senderPublicKey = accountPublicKeys[sender];
        if (senderPublicKey == null) return false;

        // 1. Both range proofs must validate against the sender's key.
        if (!rangeVerifier.verify(amountProof, senderPublicKey)) return false;
        if (!amount.equals(amountProof.getEncryptedValue())) return false;

        if (!rangeVerifier.verify(newBalanceProof, senderPublicKey)) return false;
        if (!newSenderBalance.equals(newBalanceProof.getEncryptedValue())) return false;

        // 2. The submitted newSenderBalance must encrypt the same value as
        //    (currentBalance / amount) — i.e. the sender actually has enough.
        Ciphertext current = computeBalance(sender);
        if (current == null) return false; // no funds at all

        Ciphertext expectedNewBalance = subtract(current, amount);
        if (!equivalenceVerifier.verify(equivalenceProof,
                senderPublicKey, expectedNewBalance, newSenderBalance)) {
            return false;
        }

        // 3. Apply the matrix update.
        matrix[sender][receiver] = (matrix[sender][receiver] == null)
                ? amount
                : matrix[sender][receiver].multiply(amount, group);

        return true;
    }

    public Ciphertext getEntry(int i, int j) {
        return matrix[i][j];
    }

    public Ciphertext getInitialBalance(int account) {
        return initialBalance[account];
    }

    public BigInteger getAccountPublicKey(int account) {
        return accountPublicKeys[account];
    }

    /** Homomorphic subtraction: Enc(a) · Enc(b)^{-1} = Enc(a - b). */
    private Ciphertext subtract(Ciphertext a, Ciphertext b) {
        return new Ciphertext(
                group.mul(a.c1, group.inverse(b.c1)),
                group.mul(a.c2, group.inverse(b.c2))
        );
    }
}
