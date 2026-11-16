package br.com.bry.challenge.dto;

import java.time.Instant;
import java.util.List;

public record VerificationResponse(String status, Infos infos, VerificationChecks checks, List<String> observations) {
    public record Infos(String signerName, Instant signingTime, String documentHash, String hashAlgorithm) {
    }

    public static VerificationResponse from(VerificationResult result) {
        return new VerificationResponse(result.integrityValid() && result.checks().chainTrusted() ? "VALIDO" : "INVALIDO",
                new Infos(result.signerName(), result.signingTime(), result.documentHash(), result.hashAlgorithm()),
                result.checks(), result.observations());
    }
}
