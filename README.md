# A DoS-Resistant, Privacy-Preserving GOC-Ledger

**Privacy-preserving transactions for the GOC-Ledger using additive ElGamal encryption and zero-knowledge proofs.**

A research prototype that adds *confidentiality* and *cryptographically enforced non-negative balances* to the Grow-Only-Counter Ledger (GOC-Ledger), a consensus-free, state-based CRDT ledger. Balances and transfer amounts are encrypted, yet every transaction is publicly verifiable through zero-knowledge range proofs, and the system implements and benchmarks **three different range-proof schemes** behind a single interface.

> Learning Contract project, University of Basel — Department of Mathematics and Computer Science.
> Examiner: Prof. Christian Tschudin · Supervisor: Dr. Osman Biçer.
> Built on the GOC-Ledger of E. Lavoie ([arXiv:2305.16976](https://arxiv.org/abs/2305.16976)).

---

## Table of Contents

- [What is this?](#what-is-this)
- [The problem it solves](#the-problem-it-solves)
- [How it works](#how-it-works)
- [Range-proof implementations](#range-proof-implementations)
- [Project structure](#project-structure)
- [Key code and logic](#key-code-and-logic)
- [Build & run](#build--run)
- [Interactive demo](#interactive-demo)
- [Tests](#tests)
- [Benchmark results](#benchmark-results)
- [Academic context & license](#academic-context--license)
- [Acknowledgements](#acknowledgements)

---

## What is this?

The **GOC-Ledger** models a replicated token ledger as a composition of grow-only counters. It is *consensus-free*: instead of ordering every transaction through a global consensus algorithm (as conventional blockchains do), it relies only on the conflict-free merge of its counters, which improves throughput and makes convergence easy to prove. In this implementation the ledger is a matrix in which `matrix[i][j]` holds the total amount ever transferred from account `i` to account `j`, and an account's balance is the aggregation of its inflows minus its outflows.

The original design has two drawbacks:

1. **No privacy** — balances and transfer amounts are stored in cleartext, visible to every replica.
2. **No built-in non-negativity** — strictly non-negative balances are delegated to an external per-account sequencing mechanism.

This project removes both drawbacks **inside the cryptographic layer**:

- Balances and amounts are encrypted with **additive (exponential) ElGamal**, whose additive homomorphism lets the balance aggregation run directly on ciphertexts.
- Every transaction carries a **zero-knowledge range proof** that the transferred amount and the resulting balance lie in `[0, 2ⁿ)`, restoring the non-negative-balance invariant without revealing any value.

## The problem it solves

Additive ElGamal carries the message in the *exponent*, so the plaintext space is the cyclic group `ℤ_q`, which has **no notion of a negative number**. An attempt to overspend does not produce a negative balance — it *wraps around* to a huge positive residue close to the group order `q`, which a naive ledger cannot distinguish from a legitimately large balance. The original prototype performed no balance check at all (its non-negativity proof was a placeholder that always returned `true`), so funds could be created from nothing while everything stayed encrypted.

A **range proof** is exactly the primitive that closes this hole: a wrapped-around balance ≈ `q` falls far outside `[0, 2ⁿ)` and can no longer pass verification.

## How it works

Each transaction is accompanied by a bundle of proofs, all verified by the ledger before the encrypted counter is updated:

| Proof | Guarantees |
|---|---|
| **Range proof** (amount) | the transferred amount is in `[0, 2ⁿ)` |
| **Range proof** (new balance) | the sender's remaining balance is non-negative (the overspend defence) |
| **Binding proof** (Chaum–Pedersen) | the ciphertext was produced by the holder of the sender's secret key (sender authenticity) |
| **Value-link proof** | the Pedersen bit-commitments and the ElGamal ciphertext embed the *same* plaintext |
| **Ciphertext-equivalence proof** | the submitted balance equals the balance the ledger derives homomorphically (`current − amount`) |

All proofs are non-interactive via the **Fiat–Shamir** heuristic, with a distinct **domain-separation tag** per proof type so transcripts cannot be replayed across protocols or across the DL/EC groups. After decryption, small plaintexts are recovered from `gᵐ` with a **baby-step giant-step** discrete-log solver (`O(√m)`), an improvement over the original brute-force search.

## Range-proof implementations

Three range-proof back-ends implement the same `RangeProver` / `RangeVerifier` interface, so the ledger works with any of them unchanged:

| Scheme | Group | Proof size | Source |
|---|---|---|---|
| **Bit-decomposition (DL)** | `ℤ_p*`, 2048-bit (RFC 3526 Group 14) | linear in `n` | **from scratch** |
| **Bit-decomposition (EC)** | Ristretto255 | linear in `n` | **from scratch** |
| **Bulletproof** | Ristretto255 | logarithmic in `n` | weavechain library |

The **bit-decomposition** proofs (DL and EC) are implemented from first principles — no proof library. The idea: decompose the secret value `v` into `n` bits, commit to each bit with a Pedersen commitment, prove each commitment opens to `0` or `1` with a disjunctive **OR-proof** (Cramer–Damgård–Schoenmakers), and prove the weighted product of the bit commitments equals the encrypted value (the *aggregation* check). If every bit is provably a bit, then `v = Σ bᵢ·2ⁱ ∈ [0, 2ⁿ)`.

The **Bulletproof** back-end delegates to the weavechain pure-Java port of dalek-cryptography (`number_in_range` gadget) and is included to compare a hand-rolled construction against a state-of-the-art, logarithmic-size one. External libraries are confined to (a) Ristretto255 group arithmetic and (b) the Bulletproof scheme.

## Project structure

```
src/main/java/com/goc/
├── core/    # group & ciphertext data types
│   ├── CryptoGroup, Ciphertext, KeyPair
│   └── ec/  ECCryptoGroup, ECCiphertext, ECKeyPair
├── crypto/  # additive ElGamal encryption + Fiat–Shamir hashing
│   ├── Crypto, FiatShamir, DomainTags
│   └── ec/  ECCrypto, ECFiatShamir
├── zkp/     # zero-knowledge proofs
│   ├── Proof, Prover, Verifier
│   ├── equivalence/   ciphertext-equivalence proof
│   └── range/         range proofs — three back-ends, one interface:
│       ├── bitdecomposition/   from scratch: OrProof, BindingProof, ValueLinkProof
│       └── bulletproof/        weavechain library port
├── ledger/  # privacy-preserving GOC-Ledger (matrix of ciphertexts)
│   ├── Ledger
│   └── ec/  ECLedger
└── demo/    # Spring Boot REST API + web UI + scenario runner
    ├── DemoApplication, DemoController, LedgerService
    ├── DlLedgerSession, EcLedgerSession
    └── DlScenarios, EcScenarios, BpScenarios
```

Every package has an `ec/` counterpart implementing the same protocol over Ristretto255. The demo web UI lives in `src/main/resources/static/index.html`, and the unit/integration tests and JMH benchmarks are under `src/test/java/com/goc/`. In total, ~3,700 lines of production code across 52 files and ~1,900 lines of test/benchmark code across 12 files.

## Key code and logic

**Transaction verification** — [`Ledger.submitTransaction`](src/main/java/com/goc/ledger/Ledger.java):

```text
submitTransaction(sender, receiver, amount, amountProof,
                  newSenderBalance, newBalanceProof, equivalenceProof):
  0. sender must be a registered account                          else REJECT
  1. verify amountProof against sender's key  &&  amount == proof.encVal   else REJECT
  2. verify newBalanceProof against sender's key  &&  balance == proof.encVal else REJECT
  3. current  = computeBalance(sender)            # homomorphic aggregation
     expected = current − amount                  # homomorphic subtraction
     verify equivalenceProof(expected, newSenderBalance)          else REJECT
  4. matrix[sender][receiver] += amount           # homomorphic accumulate → ACCEPT
```

**Bit-decomposition range proof** — [`BitDecompositionRangeProver`](src/main/java/com/goc/zkp/range/bitdecomposition/BitDecompositionRangeProver.java):

```text
prove(value, sk, pk = h):
    assert 0 ≤ value < 2ⁿ
    # deterministic key-bound ciphertext randomness, bound to the sender
    r = random;  R = g^r;  y = H("ENC_RANDOMNESS_DERIVE", R);  a = r + y mod q
    for each bit i:  Cᵢ = g^{bᵢ}·h^{rᵢ};  orProofᵢ = proveBit(bᵢ, rᵢ, Cᵢ, h)
    encVal  = (g^a, Π Cᵢ^{2ⁱ})                  # = (c1, c2 = g^value·h^a)
    binding = Chaum–Pedersen proof of knowledge of sk
    return RangeProof(commitments, orProofs, encVal, binding, n)
```

The disjunctive **OR-proof** (`proveBit`) runs the real branch honestly and *simulates* the fake branch by sampling its challenge/response first; the two branch challenges are forced to sum to the Fiat–Shamir challenge, which is what makes the proof sound. The EC versions are structurally identical with exponentiation → scalar multiplication and the weighted product → a weighted sum.

## Build & run

**Requirements:** JDK 25, Maven 3.9+. (Dependencies — Ristretto255 `curve25519-elisabeth`, weavechain `bulletproofs` — are pulled from Maven Central and JitPack automatically.)

```bash
# Compile and run the full test suite
mvn clean test

# Build
mvn clean package
```

## Interactive demo

A Spring Boot web application lets you drive the ledger interactively:

```bash
mvn spring-boot:run
# then open http://localhost:8080
```

The UI (and its REST API under `/api`) lets you:

- **Initialise** a ledger choosing the backend (`DL`, `EC`, or `BP`) and bit length — `POST /api/ledger/init`.
- **Transfer** funds between accounts and watch proofs being generated and verified — `POST /api/ledger/transfer`.
- **Run scenario suites** that mirror the JUnit integration tests (valid transfer, overspend, impersonation, tampered proof, …) — `GET /api/ledger/scenarios`, `POST /api/ledger/scenario`.
- **Run Bulletproof range-proof scenarios** — `GET /api/bp/scenarios`, `POST /api/bp/scenario`.

## Tests

Run with `mvn test`. Highlights:

- **`BitDecompositionRangeProverTest`** / **`ECBitDecompositionRangeProverTest`** — completeness (valid value, lower bound `0`, upper bound `2ⁿ−1`) and soundness: every way of tampering a proof (manipulated challenge, wrong public key, bit-length mismatch, corrupted aggregation, forged/spliced binding proof, tampered bit commitment) is rejected.
- **`BulletproofRangeProverTest`** — range acceptance/rejection for the library back-end.
- **`ECCryptoTest`** / **`ECCiphertextEquivalenceTest`** — encryption round-trips (with BSGS recovery), the additive homomorphism, and equivalence-proof soundness.
- **`LedgerIntegrationTest`** / **`ECLedgerIntegrationTest`** — the full transaction protocol end to end: a valid transfer is **accepted**, while overspending, an unregistered sender, an attacker impersonating another account, a tampered equivalence proof, and an account with no funds are all **rejected**; concurrent inflows accumulate correctly.

JMH benchmarks (each has a `main`, runnable from the IDE or via Maven): `BitDecompositionBenchmark`, `ECBitDecompositionBenchmark`, `BulletproofBenchmark`, `DiscreteLogBenchmark` (brute-force vs. BSGS), and `ProofSizeMeasurement`. They emit JSON; [`plot_benchmarks.py`](plot_benchmarks.py) turns that JSON into the comparison charts in [`charts/`](charts/).

## Benchmark results

Measured on an Intel Core i7-9750H (6c/12t, 2.6 GHz), 16 GB RAM, Windows 11, JDK 25, using the production 2048-bit group for DL. Representative figures at **n = 32 bits**:

| Scheme | Prover (ms) | Verifier (ms) | Proof size |
|---|---|---|---|
| Bit-decomposition (DL, 2048-bit) | 319 | 282 | 67.1 KB |
| Bit-decomposition (EC, Ristretto255) | 40.1 | 34.0 | 8.4 KB |
| Bulletproof (EC) | 60.7 | **6.5** | **995 B** |

**Takeaways:** the EC port is the fastest prover (≈8× faster than DL); the Bulletproof wins decisively on verification time and proof size (logarithmic growth, <1 KB). Cost grows linearly in `n` for the bit-decomposition schemes.

**DoS resistance (a notable finding):** the hand-written bit-decomposition verifiers are *fail-fast* — they reject a tampered proof in **under one microsecond** (≈ `4×10⁻⁴` ms), four to five orders of magnitude faster than they accept a valid one. A replica can therefore discard a flood of malformed proofs at minimal cost, making proof-flooding denial-of-service attacks economically infeasible. The Bulletproof verifier, by contrast, performs a single indivisible computation and rejects an invalid proof no faster than it accepts a valid one (3–7 ms).

## Academic context & license

This repository was produced as a **Learning Contract project at the University of Basel** (Department of Mathematics and Computer Science, Computer Networks Group), supervised by Dr. Osman Biçer and examined by Prof. Christian Tschudin. It extends the GOC-Ledger of Erick Lavoie.

It is shared for **academic and educational purposes**, and you are welcome to use, study, modify, and build upon the code for those purposes, provided you credit the author. © 2026 Ali Armağan Uygun, University of Basel. For commercial or other uses — or to have a formal open-source license (e.g. MIT) added — please contact the author.

## Acknowledgements

- **E. Lavoie**, *GOC-Ledger: State-based Conflict-Free Replicated Ledger from Grow-Only Counters*, [arXiv:2305.16976](https://arxiv.org/abs/2305.16976) — the base design this project extends.
- The Chaum–Pedersen **binding** and **ciphertext-equivalence** proof constructions build on earlier work by Jakob *(citation to be added)*.
- [weavechain/bulletproofs](https://github.com/weavechain/bulletproofs) and `curve25519-elisabeth` — Ristretto255 arithmetic and the Bulletproof implementation.
