package br.com.bry.challenge.dto;

import java.time.Instant;

/**
 * Individual verification findings, kept separate from the API's overall status.
 * Integrity covers the signature; chainTrusted covers a PKIX path to the configured root.
 * certificateTrusted also requires current chain validity. Date findings remain advisory.
 */
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
