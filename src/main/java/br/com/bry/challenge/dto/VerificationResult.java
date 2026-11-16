package br.com.bry.challenge.dto;

import java.time.Instant;
import java.util.List;

/**
 * Internal service result: signer metadata, findings and observations, without an HTTP status policy.
 * The summary flags mirror checks for service callers; VerificationResponse shapes the public JSON.
 */
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
