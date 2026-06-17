package com.goc.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot entry point for the interactive demo.
 *
 * Run:
 *   mvn spring-boot:run
 * then open http://localhost:8080 in a browser.
 *
 * The demo exposes a private-ledger playground over a small REST API:
 *   - Preset scenarios mirroring the JUnit integration tests (7/7).
 *   - Manual transfers with encrypted balances and attack modes that the
 *     verifier rejects.
 *
 * Range-proof performance (DL / EC / Bulletproofs) is compared in the JMH
 * benchmarks and charts, not here.
 */
@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
