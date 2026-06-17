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
 * JMH Benchmark: BitDecomposition Range Proof (Discrete-Log group).
 *
 * Measured dimensions:
 *   1. Baseline   — average prover & verifier time (ms)
 *   2. Rejection  — verifier time on a tampered (invalid) proof
 *   3. Throughput — operations per second
 *
 * Mirrors {@link ECBitDecompositionBenchmark} and {@link BulletproofBenchmark}
 * so all three implementations compare apples-to-apples across the same
 * bit-length sweep (4..32).
 *
 * How to run via CLI:
 *   mvn clean package
 *   java -jar target/benchmarks.jar BitDecompositionBenchmark -prof gc
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)            // Benchmark scope: shared state, more realistic
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
    // ---------------------------------------------------------------------
    @Param({"4", "8", "16", "32"})
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
    private BigInteger publicKey;

    private BitDecompositionRangeProver prover;
    private BitDecompositionRangeVerifier verifier;

    private RangeWitness witnessNormal;  // typical value
    private RangeProof proofNormal;      // precomputed valid proof (verifier benchmarks)
    private RangeProof tamperedProof;    // precomputed invalid proof (rejection benchmark)

    @Setup(Level.Trial)
    public void setup() {
        group = new CryptoGroup(P_2048, Q_2048, G_2048);
        crypto = new Crypto(group);

        var keyPair = crypto.keyGen();
        BigInteger secretKey = keyPair.secretKey;
        publicKey = keyPair.publicKey;

        prover = new BitDecompositionRangeProver(group, crypto, bitLength);
        verifier = new BitDecompositionRangeVerifier(group, bitLength);

        witnessNormal = new RangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        proofNormal = prover.prove(witnessNormal);
        tamperedProof = tamper(proofNormal);
    }

    // =====================================================================
    // GROUP 1: Baseline performance
    // =====================================================================

    /** Prover execution time for a typical value. */
    @Benchmark
    public void prover_normal(Blackhole bh) {
        bh.consume(prover.prove(witnessNormal));
    }

    /** Verifier execution time for a valid proof. */
    @Benchmark
    public void verifier_valid(Blackhole bh) {
        bh.consume(verifier.verify(proofNormal, publicKey));
    }

    // =====================================================================
    // GROUP 2: Invalid proof rejection (soundness)
    // =====================================================================

    /** Verifier must reject a tampered proof; measures rejection time. */
    @Benchmark
    public void verifier_tampered(Blackhole bh) {
        bh.consume(verifier.verify(tamperedProof, publicKey));
    }

    // =====================================================================
    // GROUP 3: Throughput (operations per second)
    // =====================================================================

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void prover_throughput(Blackhole bh) {
        bh.consume(prover.prove(witnessNormal));
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void verifier_throughput(Blackhole bh) {
        bh.consume(verifier.verify(proofNormal, publicKey));
    }

    // =====================================================================
    // Helper: tamper proof (simulate adversarial modification)
    // =====================================================================

    private RangeProof tamper(RangeProof original) {
        var commitments = original.getBitCommitments().clone();
        if (commitments.length > 0) {
            commitments[0] = commitments[0].add(BigInteger.ONE);
        }
        return new RangeProof(
                commitments,
                original.getBitProofs(),
                original.getPedersenCommitment(),
                original.getEncryptedValue(),
                original.getValueLinkProof(),
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
                .forks(2)
                .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON)
                .result("dl.json")
                .addProfiler("gc")
                .build();

        new Runner(opt).run();
    }
}
