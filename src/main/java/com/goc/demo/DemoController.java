package com.goc.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API backing the ledger-scenarios demo.
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    private final LedgerService ledgerService;

    public DemoController(LedgerService ledgerService) {
        this.ledgerService = ledgerService;
    }

    // ---- Ledger ----------------------------------------------------------

    public record InitRequest(String backend, int bitLength) {}

    public record TransferRequest(int sender, int receiver, long amount, String mode) {}

    @PostMapping("/ledger/init")
    public LedgerService.LedgerState init(@RequestBody InitRequest req) {
        return ledgerService.init(req.backend(), req.bitLength());
    }

    @GetMapping("/ledger")
    public LedgerService.LedgerState ledger() {
        return ledgerService.state();
    }

    @PostMapping("/ledger/transfer")
    public LedgerService.TransferResult transfer(@RequestBody TransferRequest req) {
        return ledgerService.transfer(req.sender(), req.receiver(), req.amount(), req.mode());
    }

    // ---- Scenario suite (mirrors the JUnit integration tests) ------------

    public record ScenarioRequest(String backend, String id) {}

    @GetMapping("/ledger/scenarios")
    public java.util.List<LedgerService.ScenarioInfo> scenarios() {
        return ledgerService.scenarios();
    }

    @PostMapping("/ledger/scenario")
    public LedgerService.ScenarioResult scenario(@RequestBody ScenarioRequest req) {
        return ledgerService.runScenario(req.backend(), req.id());
    }

    // ---- Bulletproofs range-proof tests (range-proof level, not ledger) ---

    public record BpScenarioRequest(String id) {}

    @GetMapping("/bp/scenarios")
    public java.util.List<LedgerService.ScenarioInfo> bpScenarios() {
        return ledgerService.bpScenarios();
    }

    @PostMapping("/bp/scenario")
    public LedgerService.ScenarioResult bpScenario(@RequestBody BpScenarioRequest req) {
        return ledgerService.runBpScenario(req.id());
    }
}
