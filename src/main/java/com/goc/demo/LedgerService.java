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

    public record ScenarioInfo(String id, String title, String expected) {}

    public record ScenarioResult(String id, String title, String expected,
                                 boolean accepted, boolean passed, List<String> log) {}

    /** The seven ledger integration-test scenarios, mirrored 1:1 in the demo. */
    public static final List<ScenarioInfo> SCENARIOS = List.of(
            new ScenarioInfo("SUFFICIENT",   "Transfer with enough balance",       "ACCEPT"),
            new ScenarioInfo("INSUFFICIENT", "Overspend attempt (not enough)",     "REJECT"),
            new ScenarioInfo("TAMPER",       "Tampered equivalence proof",         "REJECT"),
            new ScenarioInfo("IMPERSONATE",  "Impersonating another account",      "REJECT"),
            new ScenarioInfo("NO_FUNDS",     "Account with no balance",            "REJECT"),
            new ScenarioInfo("UNREGISTERED", "Unregistered account sends",         "REJECT"),
            new ScenarioInfo("ACCUMULATE",   "Incoming transfers add up",          "ACCEPT"),
            new ScenarioInfo("REPLAY",        "Replay a past transaction",          "REJECT"),
            new ScenarioInfo("DOUBLE_SPEND",  "Double-spend the same balance",      "REJECT"),
            new ScenarioInfo("AMOUNT_SPLICE", "Wrong amount (proof mismatch)",      "REJECT")
    );

    /** Bulletproofs range-proof correctness checks (mirrors the JUnit unit tests). */
    public static final List<ScenarioInfo> BP_SCENARIOS = List.of(
            new ScenarioInfo("VALID",        "Valid value (42)",                   "VERIFIED"),
            new ScenarioInfo("SMALL",        "Small value (1)",                    "VERIFIED"),
            new ScenarioInfo("MAX",          "Maximum value (255 = 2⁸−1)",         "VERIFIED"),
            new ScenarioInfo("NEGATIVE",     "Negative value (−1)",                "REJECTED"),
            new ScenarioInfo("OUT_OF_RANGE", "Out of range (256)",                 "REJECTED"),
            new ScenarioInfo("BIT_MISMATCH", "Wrong bit-length verifier",          "REJECTED"),
            new ScenarioInfo("TAMPERED",     "Tampered proof (flipped byte)",      "REJECTED")
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
