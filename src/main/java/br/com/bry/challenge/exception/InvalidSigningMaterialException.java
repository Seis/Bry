package br.com.bry.challenge.exception;

import java.security.GeneralSecurityException;

/**
 * Expected input failure when a PKCS12, password or signing-key selection is unusable.
 * Its domain type lets the HTTP handler return 400 while preserving the technical cause.
 */
public class InvalidSigningMaterialException extends GeneralSecurityException {
    public InvalidSigningMaterialException(String message, Throwable cause) {
        super(message, cause);
    }
}
