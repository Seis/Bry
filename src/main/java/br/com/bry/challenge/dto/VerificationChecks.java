package br.com.bry.challenge.dto;

import java.time.Instant;

public record VerificationChecks(
        boolean integrityValid,
        boolean chainTrusted,
        boolean certificateTrusted,
        boolean certificateExpired,
        boolean certificateNotYetValid,
        boolean signingTimeInFuture,
        Instant certificateValidFrom,
        Instant certificateValidUntil) {
}
