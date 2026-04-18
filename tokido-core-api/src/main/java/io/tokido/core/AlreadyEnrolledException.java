package io.tokido.core;

/**
 * Thrown when attempting to enroll a user in a factor they are already enrolled in.
 */
public class AlreadyEnrolledException extends MfaException {

    private final String userId;
    private final String factorType;

    public AlreadyEnrolledException(String userId, String factorType) {
        super("User '%s' is already enrolled in factor '%s'".formatted(userId, factorType));
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
