package io.tokido.core;

/**
 * Base exception for all MFA-related errors.
 */
public class MfaException extends RuntimeException {

    public MfaException(String message) {
        super(message);
    }

    public MfaException(String message, Throwable cause) {
        super(message, cause);
    }
}
