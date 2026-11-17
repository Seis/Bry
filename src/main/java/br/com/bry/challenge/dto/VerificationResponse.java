package br.com.bry.challenge.dto;

import java.time.Instant;
import java.util.List;

/**
 * Public /verify response, grouping metadata under infos as required by the API contract.
 * VALIDO requires integrity and chain trust; date findings are exposed as checks and observations.
 */
public record VerificationResponse(String status, Infos infos, VerificationChecks checks, List<String> observations) {
    /** Signer metadata extracted from the certificate and the attached CMS. */
    public record Infos(String signerName, Instant signingTime, String documentHash, String hashAlgorithm) {
    }

    public VerificationResponse {
        observations = List.copyOf(observations);
    }
}
