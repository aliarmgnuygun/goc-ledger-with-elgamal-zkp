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
     */
    public record ScenarioInfo(String id, String group, String title, String desc,
                               String expected) {}

    public record ScenarioResult(String id, String title, String expected,
                                 boolean accepted, boolean passed, List<String> log) {}

    /** Ledger integration scenarios, grouped by what they exercise. */
    public static final List<ScenarioInfo> SCENARIOS = List.of(
            // Honest flow — should be ACCEPTED
            new ScenarioInfo("SUFFICIENT", "Honest transfers", "A normal payment when the sender has enough money",
                    "Alice has enough balance and sends a valid payment to Bob. The ledger checks every proof and accepts the transfer. This is how an ordinary, honest payment is supposed to work.", "ACCEPT"),
            new ScenarioInfo("ACCUMULATE", "Honest transfers", "Money received from several people adds up correctly",
                    "Bob receives payments from two different senders. Even though all balances stay encrypted, the ledger adds the incoming amounts together correctly, so Bob ends up with the right total.", "ACCEPT"),
            // Overspend & balance attacks — should be REJECTED
            new ScenarioInfo("INSUFFICIENT", "Overspend & balance attacks", "Trying to spend more money than you actually have",
                    "Alice tries to send more than she owns. She cannot prove that her remaining balance would still be valid, so the ledger rejects the payment and the overspending is blocked.", "REJECT"),
            new ScenarioInfo("NO_FUNDS", "Overspend & balance attacks", "Trying to send money from an empty account",
                    "An account with a zero balance still tries to make a payment. Because there is no money to send, the ledger rejects the transfer.", "REJECT"),
            new ScenarioInfo("DOUBLE_SPEND", "Overspend & balance attacks", "Trying to spend the same money twice at the same time",
                    "Alice prepares two payments from the same starting balance, hoping both will go through. The ledger accepts only the first one and rejects the second, because by then her balance has already changed.", "REJECT"),
            new ScenarioInfo("REPLAY", "Overspend & balance attacks", "Re-sending a payment that was already used",
                    "Someone copies a payment that already went through and submits it a second time. The ledger sees that the balance no longer matches the old proof and rejects the replay.", "REJECT"),
            // Proof-integrity attacks — should be REJECTED
            new ScenarioInfo("TAMPER", "Proof-integrity attacks", "Secretly editing a valid proof after it is made",
                    "A correct payment is built, but afterwards one number inside its proof is quietly changed. When the ledger re-checks the proof, the math no longer adds up, so the payment is rejected.", "REJECT"),
            new ScenarioInfo("AMOUNT_SPLICE", "Proof-integrity attacks", "Proving one amount but actually sending another",
                    "Alice builds an honest proof for one amount but then tries to send a different amount. The ledger checks that the amount sent matches the amount proven, finds they differ, and rejects the transfer.", "REJECT"),
            // Identity & access control — should be REJECTED
            new ScenarioInfo("IMPERSONATE", "Identity & access control", "Pretending to be someone else to spend their money",
                    "An attacker uses their own secret key but tries to send money out of Alice's account. The proofs do not match Alice's registered key, so the ledger rejects the attempt.", "REJECT"),
            new ScenarioInfo("UNREGISTERED", "Identity & access control", "Sending from an account the ledger does not know",
                    "An account that was never registered on the ledger tries to send money. Because the ledger has no record of its key, the transfer is rejected.", "REJECT")
    );

    /** Bulletproofs range-proof checks, grouped by what they exercise. */
    public static final List<ScenarioInfo> BP_SCENARIOS = List.of(
            // In-range values — should VERIFY
            new ScenarioInfo("VALID", "Valid values (accepted)", "A normal number that is inside the allowed range",
                    "The number 42 is comfortably within the allowed range of 0 to about 4.3 billion (2³² − 1). The proof is built correctly and the verifier accepts it.", "VERIFIED"),
            new ScenarioInfo("SMALL", "Valid values (accepted)", "A very small number near the bottom of the range",
                    "The number 1 sits right near the lowest end of the range. Its proof still works and is accepted, showing that small values are handled correctly.", "VERIFIED"),
            new ScenarioInfo("MAX", "Valid values (accepted)", "The largest number that still fits in the range",
                    "The number 4,294,967,295 is the biggest value that fits in 32 bits (2³² − 1). It is still inside the allowed range, so its proof is accepted.", "VERIFIED"),
            // Out-of-range values — should be REJECTED
            new ScenarioInfo("NEGATIVE", "Out-of-range values (rejected)", "A negative number, which the range does not allow",
                    "The number −1 is below the allowed range. A range proof can only cover values of 0 and above, so no valid proof exists and it is rejected.", "REJECTED"),
            new ScenarioInfo("OUT_OF_RANGE", "Out-of-range values (rejected)", "A number that is too big for the range",
                    "The number 4,294,967,296 is just above the 32-bit limit, whose highest value is 4,294,967,295. It does not fit in the range, so the proof fails and is rejected.", "REJECTED"),
            // Malformed proofs / verifiers — should be REJECTED
            new ScenarioInfo("BIT_MISMATCH", "Malformed proofs (rejected)", "Checking a proof with the wrong range settings",
                    "A proof made for a 32-bit range is checked using a 16-bit verifier. The settings do not match the ones the proof was built with, so the verifier rejects it.", "REJECTED"),
            new ScenarioInfo("TAMPERED", "Malformed proofs (rejected)", "A proof that was altered after it was created",
                    "A valid proof has a single byte flipped after it was built. The verifier detects the change and rejects the corrupted proof.", "REJECTED")
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
        if (amount <= 0) {
            return new TransferResult(false,
                    List.of("Amount must be greater than 0 — a transfer of 0 moves no money and is not allowed."),
                    state());
        }
        Session.TransferOutcome outcome = session.transfer(sender, receiver, amount, mode);
        return new TransferResult(outcome.accepted(), outcome.log(), state());
    }
}
