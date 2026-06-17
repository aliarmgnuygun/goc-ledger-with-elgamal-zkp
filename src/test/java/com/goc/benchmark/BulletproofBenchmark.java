package com.goc.benchmark;

import com.goc.zkp.range.bulletproof.BulletproofRangeProof;
import com.goc.zkp.range.bulletproof.BulletproofRangeProver;
import com.goc.zkp.range.bulletproof.BulletproofRangeVerifier;
import com.goc.zkp.range.bulletproof.BulletproofRangeWitness;
import com.weavechain.zk.bulletproofs.Proof;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

/**
 * JMH Benchmark: Bulletproofs range proof (weavechain, Ristretto255).
 *
 * Measured dimensions (identical to the bit-decomposition benchmarks):
 *   1. Baseline   — average prover & verifier time (ms)
 *   2. Rejection  — verifier time on a tampered (invalid) proof
 *   3. Throughput — operations per second
 *
 * The Bulletproofs gadget caps at 63 bits, so the sweep stops at 32 —
 * matching the range the other two benchmarks now cover.
 *
 * Run via CLI:
 *   mvn clean package
 *   java -jar target/benchmarks.jar BulletproofBenchmark -prof gc \
 *        -rf json -rff bp-benchmark/bp.json
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
public class BulletproofBenchmark {

    @Param({"4", "8", "16", "32"})
    private int bitLength;

    private BulletproofRangeProver   prover;
    private BulletproofRangeVerifier verifier;

    private BulletproofRangeWitness witnessNormal;

    private BulletproofRangeProof proofNormal;
    private BulletproofRangeProof tamperedProof;

    @Setup(Level.Trial)
    public void setup() {
        prover   = new BulletproofRangeProver(bitLength);
        verifier = new BulletproofRangeVerifier(bitLength);

        witnessNormal = new BulletproofRangeWitness(5L);
        proofNormal   = prover.prove(witnessNormal);
        tamperedProof = tamper(proofNormal, prover.prove(new BulletproofRangeWitness(6L)));
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
        bh.consume(verifier.verify(proofNormal));
    }

    // =====================================================================
    // GROUP 2: Invalid proof rejection (soundness)
    // =====================================================================

    @Benchmark
    public void verifier_tampered(Blackhole bh) {
        bh.consume(verifier.verify(tamperedProof));
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
        bh.consume(verifier.verify(proofNormal));
    }

    // =====================================================================
    // Helper: tamper proof by pairing a valid R1CS proof with the
    // commitment of a *different* value, so verification must fail.
    // =====================================================================

    private BulletproofRangeProof tamper(BulletproofRangeProof original, BulletproofRangeProof other) {
        Proof tampered = new Proof(
                original.getProof().getProof(),     // valid R1CS proof for value 5
                other.getProof().getCommitments()); // commitment to a different value
        return new BulletproofRangeProof(tampered, original.getBitLength());
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(".*BulletproofBenchmark.*")
                .forks(2)
                .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON)
                .result("bp.json")
                .addProfiler("gc")
                .build();
        new Runner(opt).run();
    }
}
