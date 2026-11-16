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

    public static VerificationResponse from(VerificationResult result) {
        return new VerificationResponse(result.integrityValid() && result.checks().chainTrusted() ? "VALIDO" : "INVALIDO",
                new Infos(result.signerName(), result.signingTime(), result.documentHash(), result.hashAlgorithm()),
                result.checks(), result.observations());
    }
}
