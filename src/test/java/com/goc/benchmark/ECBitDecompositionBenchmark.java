package com.goc.benchmark;

import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.goc.crypto.ec.ECCrypto;
import com.goc.zkp.range.bitdecomposition.ec.ECBitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.ec.ECBitDecompositionRangeVerifier;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeWitness;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

/**
 * JMH Benchmark: EC (Ristretto255) Bit-Decomposition Range Proof.
 *
 * Measured dimensions:
 *   1. Baseline   — average prover & verifier time (ms)
 *   2. Rejection  — verifier time on a tampered (invalid) proof
 *   3. Throughput — operations per second
 *
 * Mirrors {@link BitDecompositionBenchmark} (Discrete-Log group) and
 * {@link BulletproofBenchmark} so the implementations compare
 * apples-to-apples across the same bit-length sweep (4..32).
 *
 * Run via CLI:
 *   mvn clean package
 *   java -jar target/benchmarks.jar ECBitDecompositionBenchmark -prof gc
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 10, time = 2)
@Fork(value = 2, jvmArgsAppend = {
        "-Xms512m", "-Xmx2g",
        "-XX:+UseG1GC",
        "-XX:+AlwaysPreTouch"
})
public class ECBitDecompositionBenchmark {

    @Param({"4", "8", "16", "32"})
    private int bitLength;

    // ---------------------------------------------------------------------
    // Cryptographic state
    // ---------------------------------------------------------------------
    private ECCryptoGroup group;
    private ECCrypto crypto;
    private RistrettoElement publicKey;

    private ECBitDecompositionRangeProver prover;
    private ECBitDecompositionRangeVerifier verifier;

    private ECRangeWitness witnessNormal;
    private ECRangeProof proofNormal;     // precomputed valid proof
    private ECRangeProof tamperedProof;   // precomputed invalid proof

    @Setup(Level.Trial)
    public void setup() {
        group = new ECCryptoGroup();
        crypto = new ECCrypto(group);

        ECKeyPair keyPair = crypto.keyGen();
        Scalar secretKey = keyPair.secretKey;
        publicKey = keyPair.publicKey;

        prover = new ECBitDecompositionRangeProver(group, crypto, bitLength);
        verifier = new ECBitDecompositionRangeVerifier(group, bitLength);

        witnessNormal = new ECRangeWitness(BigInteger.valueOf(5), secretKey, publicKey);
        proofNormal = prover.prove(witnessNormal);
        tamperedProof = tamper(proofNormal);
    }

    // =====================================================================
    // GROUP 1: Baseline performance
    // =====================================================================

    @Benchmark
    public void prover_normal(Blackhole bh) {
        bh.consume(prover.prove(witnessNormal));
    }

    @Benchmark
    public void verifier_valid(Blackhole bh) {
        bh.consume(verifier.verify(proofNormal, publicKey));
    }

    // =====================================================================
    // GROUP 2: Invalid proof rejection (soundness)
    // =====================================================================

    @Benchmark
    public void verifier_tampered(Blackhole bh) {
        bh.consume(verifier.verify(tamperedProof, publicKey));
    }

    // =====================================================================
    // GROUP 3: Throughput
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
    // Helper: tamper proof by corrupting a bit commitment
    // =====================================================================

    private ECRangeProof tamper(ECRangeProof original) {
        var commitments = original.getBitCommitments().clone();
        if (commitments.length > 0) {
            // Add the basepoint to the first commitment so it no longer
            // matches its OR-proof / the aggregated c2.
            commitments[0] = commitments[0].add(group.g);
        }
        return new ECRangeProof(
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
    // Main: writes ec.json
    // =====================================================================
    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(".*ECBitDecompositionBenchmark.*")
                .forks(2)
                .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON)
                .result("ec.json")
                .addProfiler("gc")
                .build();

        new Runner(opt).run();
    }
}
