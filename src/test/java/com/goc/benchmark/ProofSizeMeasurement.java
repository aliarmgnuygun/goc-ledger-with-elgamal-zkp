package com.goc.benchmark;

import com.goc.core.CryptoGroup;
import com.goc.core.KeyPair;
import com.goc.core.ec.ECCryptoGroup;
import com.goc.core.ec.ECKeyPair;
import com.goc.crypto.Crypto;
import com.goc.crypto.ec.ECCrypto;
import com.goc.zkp.range.RangeProof;
import com.goc.zkp.range.RangeWitness;
import com.goc.zkp.range.bitdecomposition.BindingProof;
import com.goc.zkp.range.bitdecomposition.BitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.OrProof;
import com.goc.zkp.range.bitdecomposition.ec.ECBindingProof;
import com.goc.zkp.range.bitdecomposition.ec.ECBitDecompositionRangeProver;
import com.goc.zkp.range.bitdecomposition.ec.ECOrProof;
import com.goc.zkp.range.ec.ECRangeProof;
import com.goc.zkp.range.ec.ECRangeWitness;
import com.goc.zkp.range.bulletproof.BulletproofRangeProof;
import com.goc.zkp.range.bulletproof.BulletproofRangeProver;
import com.goc.zkp.range.bulletproof.BulletproofRangeWitness;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Measures the serialized proof size (in bytes) of each range-proof
 * implementation across a sweep of bit lengths, and writes the result
 * to {@code proof-sizes.json} for plotting.
 *
 * This is deterministic and fast (no JIT warm-up needed), so it runs as
 * a plain main method rather than a JMH benchmark.
 *
 * Run:
 *   mvn test-compile
 *   mvn exec:java -Dexec.mainClass=com.goc.benchmark.ProofSizeMeasurement \
 *       -Dexec.classpathScope=test
 * or simply run this main() from the IDE.
 */
public class ProofSizeMeasurement {

    private static final int[] BIT_LENGTHS    = {4, 8, 16, 32};
    private static final int[] BP_BIT_LENGTHS = {4, 8, 16, 32}; // gadget caps at 63 bits
    private static final long  SAMPLE_VALUE   = 5L;

    // 2048-bit RFC 3526 Group 14 parameters (same as the DL benchmark)
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

    public static void main(String[] args) throws IOException {
        Map<String, Map<Integer, Integer>> sizes = new LinkedHashMap<>();
        sizes.put("DL bit-decomp",  measureDl());
        sizes.put("EC bit-decomp",  measureEc());
        sizes.put("Bulletproofs",   measureBulletproof());

        writeJson(sizes, "proof-sizes.json");

        // Console summary
        System.out.println("\nProof size (bytes):");
        System.out.printf("%-16s", "bits");
        for (String impl : sizes.keySet()) System.out.printf("%18s", impl);
        System.out.println();
        for (int bits : BIT_LENGTHS) {
            System.out.printf("%-16d", bits);
            for (Map<Integer, Integer> impl : sizes.values()) {
                Integer v = impl.get(bits);
                System.out.printf("%18s", v == null ? "-" : v.toString());
            }
            System.out.println();
        }
    }

    // -----------------------------------------------------------------
    // DL bit-decomposition
    // -----------------------------------------------------------------

    private static Map<Integer, Integer> measureDl() {
        CryptoGroup group  = new CryptoGroup(P_2048, Q_2048, G_2048);
        Crypto      crypto = new Crypto(group);
        KeyPair     kp     = crypto.keyGen();

        Map<Integer, Integer> out = new LinkedHashMap<>();
        for (int bits : BIT_LENGTHS) {
            var prover = new BitDecompositionRangeProver(group, crypto, bits);
            var proof  = prover.prove(new RangeWitness(
                    BigInteger.valueOf(SAMPLE_VALUE), kp.secretKey, kp.publicKey));
            out.put(bits, sizeDl(proof));
        }
        return out;
    }

    private static int sizeDl(RangeProof p) {
        int total = 0;
        for (BigInteger c : p.getBitCommitments()) total += c.toByteArray().length;
        for (OrProof or : p.getBitProofs()) {
            total += or.commitment().toByteArray().length;
            total += or.a0().toByteArray().length;
            total += or.a1().toByteArray().length;
            total += or.c0().toByteArray().length;
            total += or.c1().toByteArray().length;
            total += or.z0().toByteArray().length;
            total += or.z1().toByteArray().length;
        }
        total += p.getPedersenCommitment().toByteArray().length;
        total += p.getEncryptedValue().c1.toByteArray().length;
        total += p.getEncryptedValue().c2.toByteArray().length;
        var lp = p.getValueLinkProof();
        total += lp.t1().toByteArray().length;
        total += lp.t2().toByteArray().length;
        total += lp.zv().toByteArray().length;
        total += lp.za().toByteArray().length;
        total += lp.zs().toByteArray().length;
        BindingProof b = p.getBindingProof();
        total += b.R().toByteArray().length;
        total += b.commitmentK1().toByteArray().length;
        total += b.commitmentK2().toByteArray().length;
        total += b.responseS().toByteArray().length;
        return total;
    }

    // -----------------------------------------------------------------
    // EC bit-decomposition
    // -----------------------------------------------------------------

    private static Map<Integer, Integer> measureEc() {
        ECCryptoGroup group  = new ECCryptoGroup();
        ECCrypto      crypto = new ECCrypto(group);
        ECKeyPair     kp     = crypto.keyGen();

        Map<Integer, Integer> out = new LinkedHashMap<>();
        for (int bits : BIT_LENGTHS) {
            var prover = new ECBitDecompositionRangeProver(group, crypto, bits);
            var proof  = prover.prove(new ECRangeWitness(
                    BigInteger.valueOf(SAMPLE_VALUE), kp.secretKey, kp.publicKey));
            out.put(bits, sizeEc(proof));
        }
        return out;
    }

    private static int sizeEc(ECRangeProof p) {
        int total = 0;
        for (var c : p.getBitCommitments()) total += c.compress().toByteArray().length;
        for (ECOrProof or : p.getBitProofs()) {
            total += or.commitment().compress().toByteArray().length;
            total += or.a0().compress().toByteArray().length;
            total += or.a1().compress().toByteArray().length;
            total += or.c0().toByteArray().length;
            total += or.c1().toByteArray().length;
            total += or.z0().toByteArray().length;
            total += or.z1().toByteArray().length;
        }
        total += p.getPedersenCommitment().compress().toByteArray().length;
        total += p.getEncryptedValue().c1.compress().toByteArray().length;
        total += p.getEncryptedValue().c2.compress().toByteArray().length;
        var lp = p.getValueLinkProof();
        total += lp.t1().compress().toByteArray().length;
        total += lp.t2().compress().toByteArray().length;
        total += lp.zv().toByteArray().length;
        total += lp.za().toByteArray().length;
        total += lp.zs().toByteArray().length;
        ECBindingProof b = p.getBindingProof();
        total += b.R().compress().toByteArray().length;
        total += b.commitmentK1().compress().toByteArray().length;
        total += b.commitmentK2().compress().toByteArray().length;
        total += b.responseS().toByteArray().length;
        return total;
    }

    // -----------------------------------------------------------------
    // Bulletproofs (weavechain serialization)
    // -----------------------------------------------------------------

    private static Map<Integer, Integer> measureBulletproof() {
        Map<Integer, Integer> out = new LinkedHashMap<>();
        for (int bits : BP_BIT_LENGTHS) {
            try {
                var prover = new BulletproofRangeProver(bits);
                BulletproofRangeProof proof = prover.prove(new BulletproofRangeWitness(SAMPLE_VALUE));
                out.put(bits, proof.getProof().serialize().length);
            } catch (Exception e) {
                System.err.println("Bulletproof size skipped for " + bits + " bits: " + e.getMessage());
            }
        }
        return out;
    }

    // -----------------------------------------------------------------
    // JSON output (manual, no external dependency)
    // -----------------------------------------------------------------

    private static void writeJson(Map<String, Map<Integer, Integer>> sizes, String path) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        int implIdx = 0;
        for (var implEntry : sizes.entrySet()) {
            sb.append("  \"").append(implEntry.getKey()).append("\": {");
            int i = 0;
            for (var e : implEntry.getValue().entrySet()) {
                if (i > 0) sb.append(", ");
                sb.append("\"").append(e.getKey()).append("\": ").append(e.getValue());
                i++;
            }
            sb.append("}");
            if (++implIdx < sizes.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("}\n");

        try (FileWriter w = new FileWriter(path)) {
            w.write(sb.toString());
        }
        System.out.println("Saved: " + path);
    }
}
