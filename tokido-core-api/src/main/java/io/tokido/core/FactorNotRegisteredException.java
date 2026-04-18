package io.tokido.core;

/**
 * Thrown when referencing a factor type that was not registered with the MfaManager.
 */
public class FactorNotRegisteredException extends MfaException {

    private final String factorType;

    public FactorNotRegisteredException(String factorType) {
        super("No factor provider registered for type '%s'".formatted(factorType));
        this.factorType = factorType;
    }

    public String factorType() {
        return factorType;
    }
}
