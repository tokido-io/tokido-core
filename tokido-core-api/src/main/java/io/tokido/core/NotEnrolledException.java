package io.tokido.core;

/**
 * Thrown when attempting to verify or unenroll a user who is not enrolled in the given factor.
 */
public class NotEnrolledException extends MfaException {

    private final String userId;
    private final String factorType;

    public NotEnrolledException(String userId, String factorType) {
        super("User '%s' is not enrolled in factor '%s'".formatted(userId, factorType));
        this.userId = userId;
        this.factorType = factorType;
    }

    public String userId() {
        return userId;
    }

    public String factorType() {
        return factorType;
    }
}
