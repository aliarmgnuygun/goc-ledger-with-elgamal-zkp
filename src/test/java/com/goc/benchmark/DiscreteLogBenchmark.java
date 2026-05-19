package com.goc.benchmark;

import com.goc.core.CryptoGroup;
import com.goc.crypto.Crypto;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

/**
 * JMH Benchmark: Discrete Logarithm Resolution
 * Compares Brute-Force vs Baby-step Giant-step (BSGS) performance.
 *
 * Focuses on worst-case scenarios where the secret value is near maxMessage.
 */
@BenchmarkMode({Mode.AverageTime, Mode.Throughput})
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(value = 2, jvmArgsAppend = {
        "-Xms512m",
        "-Xmx4g",
        "-XX:+UseG1GC"
})
public class DiscreteLogBenchmark {

    // Test the scalability: 10 Thousand, 100 Thousand, 1 Million
    @Param({"10000", "100000", "1000000"})
    private long maxMessage;

    // 2048-bit RFC 3526 Group 14 parameters (production-grade)
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

    private static final BigInteger Q_2048 = P_2048.subtract(BigInteger.ONE).divide(BigInteger.TWO);
    private static final BigInteger G_2048 = BigInteger.TWO;

    private CryptoGroup group;
    private Crypto crypto;
    private BigInteger targetValue;

    @Setup(Level.Trial)
    public void setup() {
        group = new CryptoGroup(P_2048, Q_2048, G_2048);
        crypto = new Crypto(group);

        // Worst-case scenario: the secret value is at the very end of the search space
        long secretX = maxMessage - 1;

        // targetValue = g^secretX mod p
        targetValue = group.pow(group.g, BigInteger.valueOf(secretX));
    }

    @Benchmark
    public void brute_force_log(Blackhole bh) {
        bh.consume(crypto.bruteForceLog(targetValue, maxMessage));
    }

    @Benchmark
    public void bsgs_log(Blackhole bh) {
        bh.consume(crypto.babyStepGiantStepLog(targetValue, maxMessage, group));
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(".*DiscreteLogBenchmark.*")
                .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON)
                .result("discrete-log-benchmark.json")
                .addProfiler("gc") // Crucial for observing HashMap allocation costs in BSGS
                .build();

        new Runner(opt).run();
    }
}
