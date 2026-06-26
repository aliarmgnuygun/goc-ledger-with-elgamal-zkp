package com.goc.demo;

import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Stateful (single in-memory session) wrapper around the privacy-preserving
 * ledger for the web demo. A session is created per backend (DL or EC) with
 * three pre-funded accounts. Transfers can be run honestly or in one of
 * several attack modes to show that the zero-knowledge verifier rejects them.
 */
@Service
public class LedgerService {

    private Session session;

    public record AccountView(int id, String name, String encC1, String encC2, long plainBalance) {}

    public record LedgerState(boolean ok, String backend, int bitLength,
                              List<AccountView> accounts, String note) {}

    public record TransferResult(boolean accepted, List<String> log, LedgerState state) {}

    /**
     * One demo scenario.
     *
     * @param group    section it is shown under (so related checks sit together)
     * @param title    short, human-readable name
     * @param desc     one line on WHAT the scenario verifies (not how)
     * @param expected the verdict the verifier should reach
     * @param inSuite  true if it mirrors a real JUnit test; false if it is a demo-only extra
     */
    public record ScenarioInfo(String id, String group, String title, String desc,
                               String expected, boolean inSuite) {}

    public record ScenarioResult(String id, String title, String expected,
                                 boolean accepted, boolean passed, List<String> log) {}

    /**
     * Ledger integration scenarios, grouped by what they exercise. The first 7
     * mirror {@code LedgerIntegrationTest}/{@code ECLedgerIntegrationTest} 1:1;
     * the 3 marked {@code inSuite=false} are demo-only attack extras.
     */
    public static final List<ScenarioInfo> SCENARIOS = List.of(
            // Honest flow — should be ACCEPTED
            new ScenarioInfo("SUFFICIENT", "Honest transfers", "Transfer with enough balance",
                    "The happy path: a funded sender's valid transfer is accepted.", "ACCEPT", true),
            new ScenarioInfo("ACCUMULATE", "Honest transfers", "Incoming transfers add up",
                    "Several incoming transfers sum correctly on the encrypted balance (homomorphic addition).", "ACCEPT", true),
            // Overspend & balance attacks — should be REJECTED
            new ScenarioInfo("INSUFFICIENT", "Overspend & balance attacks", "Overspend attempt (not enough)",
                    "Spending more than you own: no valid new-balance proof exists, so it is blocked.", "REJECT", true),
            new ScenarioInfo("NO_FUNDS", "Overspend & balance attacks", "Account with no balance",
                    "A sender with zero balance cannot transfer anything.", "REJECT", true),
            new ScenarioInfo("DOUBLE_SPEND", "Overspend & balance attacks", "Double-spend the same balance",
                    "Two transfers built on the same balance — only one can succeed.", "REJECT", false),
            new ScenarioInfo("REPLAY", "Overspend & balance attacks", "Replay a past transaction",
                    "Re-submitting an old transaction's proofs fails once the balance has moved.", "REJECT", false),
            // Proof-integrity attacks — should be REJECTED
            new ScenarioInfo("TAMPER", "Proof-integrity attacks", "Tampered equivalence proof",
                    "Changing one number inside a valid proof is caught by the verifier.", "REJECT", true),
            new ScenarioInfo("AMOUNT_SPLICE", "Proof-integrity attacks", "Wrong amount (proof mismatch)",
                    "The transferred ciphertext must match the amount proven by the range proof.", "REJECT", false),
            // Identity & access control — should be REJECTED
            new ScenarioInfo("IMPERSONATE", "Identity & access control", "Impersonating another account",
                    "Proofs are bound to the registered key; sending with the wrong key fails.", "REJECT", true),
            new ScenarioInfo("UNREGISTERED", "Identity & access control", "Unregistered account sends",
                    "An account whose public key is not registered cannot send.", "REJECT", true)
    );

    /**
     * Bulletproofs range-proof checks. The first 6 mirror
     * {@code BulletproofRangeProverTest} 1:1; the {@code inSuite=false} one is a
     * demo-only tamper extra.
     */
    public static final List<ScenarioInfo> BP_SCENARIOS = List.of(
            // In-range values — should VERIFY
            new ScenarioInfo("VALID", "Valid values (accepted)", "Valid value (42)",
                    "A typical in-range value produces a proof that verifies.", "VERIFIED", true),
            new ScenarioInfo("SMALL", "Valid values (accepted)", "Small value (1)",
                    "A low boundary value still verifies.", "VERIFIED", true),
            new ScenarioInfo("MAX", "Valid values (accepted)", "Maximum value (255 = 2⁸−1)",
                    "The largest in-range value verifies.", "VERIFIED", true),
            // Out-of-range values — should be REJECTED
            new ScenarioInfo("NEGATIVE", "Out-of-range values (rejected)", "Negative value (−1)",
                    "A negative value has no valid range proof.", "REJECTED", true),
            new ScenarioInfo("OUT_OF_RANGE", "Out-of-range values (rejected)", "Out of range (256)",
                    "A value above 2⁸−1 cannot be proven in range.", "REJECTED", true),
            // Malformed proofs / verifiers — should be REJECTED
            new ScenarioInfo("BIT_MISMATCH", "Malformed proofs (rejected)", "Wrong bit-length verifier",
                    "Verifying a proof against a different bit-length fails.", "REJECTED", true),
            new ScenarioInfo("TAMPERED", "Malformed proofs (rejected)", "Tampered proof (flipped byte)",
                    "Flipping a byte in a valid proof makes verification fail.", "REJECTED", false)
    );

    public List<ScenarioInfo> scenarios() {
        return SCENARIOS;
    }

    public List<ScenarioInfo> bpScenarios() {
        return BP_SCENARIOS;
    }

    public ScenarioResult runBpScenario(String id) {
        ScenarioInfo info = BP_SCENARIOS.stream()
                .filter(s -> s.id().equals(id)).findFirst().orElse(null);
        if (info == null) {
            return new ScenarioResult(id, "?", "?", false, false,
                    List.of("Unknown scenario: " + id));
        }
        List<String> log = new java.util.ArrayList<>();
        boolean accepted;
        try {
            accepted = new BpScenarios().run(id, log);
        } catch (Exception e) {
            log.add("Error while running scenario: " + e.getMessage());
            accepted = false;
        }
        boolean expectVerify = "VERIFIED".equals(info.expected());
        boolean passed = (accepted == expectVerify);
        return new ScenarioResult(id, info.title(), info.expected(), accepted, passed, log);
    }

    public ScenarioResult runScenario(String backend, String id) {
        ScenarioInfo info = SCENARIOS.stream()
                .filter(s -> s.id().equals(id)).findFirst().orElse(null);
        if (info == null) {
            return new ScenarioResult(id, "?", "?", false, false,
                    List.of("Unknown scenario: " + id));
        }
        List<String> log = new java.util.ArrayList<>();
        boolean accepted;
        try {
            accepted = switch (backend.toUpperCase()) {
                case "DL" -> new DlScenarios().run(id, log);
                case "EC" -> new EcScenarios().run(id, log);
                default -> {
                    log.add("Unknown backend: " + backend);
                    yield false;
                }
            };
        } catch (Exception e) {
            log.add("Error while running scenario: " + e.getMessage());
            accepted = false;
        }
        boolean expectAccept = "ACCEPT".equals(info.expected());
        boolean passed = (accepted == expectAccept);
        return new ScenarioResult(id, info.title(), info.expected(), accepted, passed, log);
    }

    /** Common contract both backend sessions implement. */
    public interface Session {
        String backend();
        int bitLength();
        List<AccountView> accounts();
        /** mode: NORMAL | OVERSPEND | IMPERSONATE | TAMPER */
        TransferOutcome transfer(int sender, int receiver, long amount, String mode);

        record TransferOutcome(boolean accepted, List<String> log) {}
    }

    public synchronized LedgerState init(String backend, int bitLength) {
        if (bitLength <= 0 || bitLength > 32) {
            return new LedgerState(false, backend, bitLength, List.of(),
                    "bitLength must be between 1 and 32 for the demo balances");
        }
        session = switch (backend.toUpperCase()) {
            case "DL" -> new DlLedgerSession(bitLength);
            case "EC" -> new EcLedgerSession(bitLength);
            default   -> null;
        };
        if (session == null) {
            return new LedgerState(false, backend, bitLength, List.of(),
                    "Unknown backend: " + backend + " (use DL or EC)");
        }
        return state();
    }

    public synchronized LedgerState state() {
        if (session == null) {
            return new LedgerState(false, "-", 0, List.of(),
                    "The ledger has not been started yet");
        }
        return new LedgerState(true, session.backend(), session.bitLength(),
                session.accounts(),
                "The network sees only the encrypted balances (Enc). The plain values "
                        + "are shown only by decrypting with the demo key.");
    }

    public synchronized TransferResult transfer(int sender, int receiver, long amount, String mode) {
        if (session == null) {
            return new TransferResult(false,
                    List.of("Start the ledger first"), state());
        }
        if (sender == receiver) {
            return new TransferResult(false,
                    List.of("Sender and receiver must be different"), state());
        }
        if (amount < 0) {
            return new TransferResult(false,
                    List.of("Amount cannot be negative"), state());
        }
        Session.TransferOutcome outcome = session.transfer(sender, receiver, amount, mode);
        return new TransferResult(outcome.accepted(), outcome.log(), state());
    }
}
