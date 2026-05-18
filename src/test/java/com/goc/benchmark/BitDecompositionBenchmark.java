package com.goc.benchmark;

import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeWitness;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeVerifier;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive JMH Benchmark: BitDecomposition Range Proof
 *
 * Measured dimensions:
 * 1. Average Prover & Verifier time (ms)
 * 2. Boundary values: 0, max-1, max, max+1 (overflow test)
 * 3. Invalid proof rejection speed (tampered proof check)
 * 4. Memory allocation (@AuxCounters + GC pressure)
 * 5. Usage of 2048-bit production parameters
 *
 * How to run via CLI:
 * mvn clean package
 * java -jar target/benchmarks.jar BitDecompositionBenchmark -prof gc
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)            // Benchmark scope instead of Thread: shared state, more realistic
@Warmup(iterations = 5, time = 2)  // Ensure JIT is fully warmed up
@Measurement(iterations = 10, time = 2)
@Fork(value = 2, jvmArgsAppend = {
        "-Xms512m", "-Xmx2g",
        "-XX:+UseG1GC",
        "-XX:+AlwaysPreTouch"       // Pre-touch heap to reduce GC jitter
})
public class BitDecompositionBenchmark {

    // ---------------------------------------------------------------------
    // Parameter: number of bits in the range proof
    // Controls proof size and computational complexity
    // ---------------------------------------------------------------------
    @Param({"4", "8", "16", "32", "64"})
    private int bitLength;

    // -------------------------------------------------------------------------
    // 2048-bit RFC 3526 Group 14 parameters (production-grade)
    // -------------------------------------------------------------------------
    private static final BigInteger P_2048 = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

    // q = (p-1)/2  (safe prime, Sophie Germain structure)
    private static final BigInteger Q_2048 = P_2048.subtract(BigInteger.ONE).divide(BigInteger.TWO);
    private static final BigInteger G_2048 = BigInteger.TWO;

    // ---------------------------------------------------------------------
    // Cryptographic state
    // ---------------------------------------------------------------------
    private CryptoGroup group;
    private Crypto crypto;
    private BigInteger secretKey;
    private BigInteger publicKey;

    private BitDecompositionRangeProver prover;
    private BitDecompositionRangeVerifier verifier;

    // ---------------------------------------------------------------------
    // Witnesses (test inputs)
    // ---------------------------------------------------------------------
    private RangeWitness witnessNormal; // typical value
    private RangeWitness witnessZero;   // lower bound
    private RangeWitness witnessMax;    // upper bound
    private RangeWitness witnessOver;   // invalid (out-of-range)

    // ---------------------------------------------------------------------
    // Precomputed proofs (used for verifier benchmarks)
    // Avoids measuring prover inside verifier tests
    // ---------------------------------------------------------------------
    private RangeProof proofNormal;
    private RangeProof proofMax;
    private RangeProof tamperedProof;

    // ---------------------------------------------------------------------
    // Setup (executed once per benchmark run)
    // ---------------------------------------------------------------------
    @Setup(Level.Trial)
    public void setup() {
        group = new CryptoGroup(P_2048, Q_2048, G_2048);
        crypto = new Crypto(group);

        var keyPair = crypto.keyGen();
        secretKey = keyPair.secretKey;
        publicKey = keyPair.publicKey;

        prover = new BitDecompositionRangeProver(group, crypto, bitLength);
        verifier = new BitDecompositionRangeVerifier(group, publicKey, bitLength);

        BigInteger max = BigInteger.TWO.pow(bitLength).subtract(BigInteger.ONE);

        witnessNormal = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        witnessZero = new RangeWitness(BigInteger.ZERO, secretKey, publicKey);
        witnessMax = new RangeWitness(max, secretKey, publicKey);
        witnessOver = new RangeWitness(BigInteger.TWO.pow(bitLength), secretKey, publicKey);

        // Precompute valid proofs for verifier benchmarks
        proofNormal = prover.prove(witnessNormal);
        proofMax = prover.prove(witnessMax);

        // Create an invalid proof by tampering
        tamperedProof = tamper(proofNormal);
    }

    // =====================================================================
    // GROUP 1: Baseline performance
    // =====================================================================

    /**
     * Measures prover execution time for a typical value.
     */
    @Benchmark
    public void prover_normal(Blackhole bh) {
        bh.consume(prover.prove(witnessNormal));
    }

    /**
     * Measures verifier execution time for a valid proof.
     */
    @Benchmark
    public void verifier_valid(Blackhole bh) {
        bh.consume(verifier.verify(proofNormal));
    }

    // =====================================================================
    // GROUP 2: Boundary conditions
    // =====================================================================

    /**
     * Lower bound test (value = 0).
     */
    @Benchmark
    public void prover_zero(Blackhole bh) {
        bh.consume(prover.prove(witnessZero));
    }

    /**
     * Upper bound test (value = 2^n - 1).
     */
    @Benchmark
    public void prover_max(Blackhole bh) {
        bh.consume(prover.prove(witnessMax));
    }

    /**
     * Out-of-range value test.
     * <p>
     * Expected behavior:
     * - Prover should fail fast (exception)
     * - Should NOT take same time as valid proof
     * <p>
     * Important for detecting potential timing side channels.
     */
    @Benchmark
    public void prover_overflow() {
        try {
            prover.prove(witnessOver);
        } catch (Exception ignored) {
            // expected
        }
    }

    /**
     * Verifier performance at upper boundary.
     */
    @Benchmark
    public void verifier_max(Blackhole bh) {
        bh.consume(verifier.verify(proofMax));
    }

    // =====================================================================
    // GROUP 3: Invalid proof rejection
    // =====================================================================

    /**
     * Verifier should reject tampered proofs.
     * <p>
     * Timing comparison vs valid proofs helps detect:
     * - early exit behavior
     * - potential timing leaks
     */
    @Benchmark
    public void verifier_tampered(Blackhole bh) {
        bh.consume(verifier.verify(tamperedProof));
    }

    // =====================================================================
    // GROUP 4: Throughput (operations per second)
    // =====================================================================

    /**
     * Prover throughput (ops/sec).
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void prover_throughput(Blackhole bh) {
        bh.consume(prover.prove(witnessNormal));
    }

    /**
     * Verifier throughput (ops/sec).
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void verifier_throughput(Blackhole bh) {
        bh.consume(verifier.verify(proofNormal));
    }

    // =====================================================================
    // GROUP 5: Latency distribution (p50, p95, p99)
    // =====================================================================

    /**
     * Prover latency sampling.
     * Useful for tail latency analysis (p99).
     */
    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    public void prover_sample(Blackhole bh) {
        bh.consume(prover.prove(witnessNormal));
    }

    /**
     * Verifier latency sampling.
     */
    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    public void verifier_sample(Blackhole bh) {
        bh.consume(verifier.verify(proofNormal));
    }

    // =====================================================================
    // Helper: Tamper proof (simulate adversarial modification)
    // =====================================================================

    /**
     * Produces a modified (invalid) proof by corrupting ciphertext.
     * This simulates a malicious actor attempting to bypass verification.
     */
    private RangeProof tamper(RangeProof original) {
        var commitments = original.getBitCommitments().clone();

        if (commitments.length > 0) {
            commitments[0] = commitments[0].add(BigInteger.ONE);
        }

        return new RangeProof(
                commitments,
                original.getBitProofs(),
                original.getEncryptedValue(),
                original.getBindingProof(),
                original.getBitLength()
        );
    }

    // =====================================================================
    // Main method (JSON output + profiling)
    // =====================================================================
    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(".*BitDecompositionBenchmark.*")

                // JVM forks (important for stable results)
                .forks(2)

                // Output format → JSON (for analysis)
                .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON)

                // Output file
                .result("benchmark-results.json")

                // Profilers
                .addProfiler("gc")     // memory allocation & GC
                .addProfiler("stack")  // hotspot methods

                .build();

        new Runner(opt).run();
    }
}