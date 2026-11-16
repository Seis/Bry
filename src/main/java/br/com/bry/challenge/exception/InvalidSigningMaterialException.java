package br.com.bry.challenge.exception;

import java.security.GeneralSecurityException;

public class InvalidSigningMaterialException extends GeneralSecurityException {
    public InvalidSigningMaterialException(String message, Throwable cause) {
        super(message, cause);
    }
}
