package br.com.bry.challenge.dto;

import java.time.Instant;
import java.util.List;

public record VerificationResult(
        boolean integrityValid,
        boolean certificateTrusted,
        String signerName,
        Instant signingTime,
        String documentHash,
        String hashAlgorithm,
        VerificationChecks checks,
        List<String> observations) {
    public VerificationResult {
        observations = List.copyOf(observations);
    }
}
