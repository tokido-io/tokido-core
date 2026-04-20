package io.tokido.core.totp;

/**
 * Configuration for the TOTP factor provider.
 * Use fluent setters to customize, or call {@link #defaults()} for standard values.
 */
public class TotpConfig {

    int secretLength = 20;
    int codeLength = 6;
    int timeStepSeconds = 30;
    int windowSize = 1;
    String algorithm = "HmacSHA1";
    String issuer = "App";
    boolean requiresConfirmation = true;

    public static TotpConfig defaults() {
        return new TotpConfig();
    }

    public TotpConfig secretLength(int secretLength) {
        this.secretLength = secretLength;
        return this;
    }

    public TotpConfig codeLength(int codeLength) {
        this.codeLength = codeLength;
        return this;
    }

    public TotpConfig timeStepSeconds(int timeStepSeconds) {
        this.timeStepSeconds = timeStepSeconds;
        return this;
    }

    public TotpConfig windowSize(int windowSize) {
        this.windowSize = windowSize;
        return this;
    }

    public TotpConfig algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public TotpConfig issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Whether TOTP enrollment follows the two-step confirm flow. Defaults to {@code true}.
     * Set to {@code false} for trusted server-side provisioning where the factor should be
     * immediately active without a separate {@code confirmEnrollment} step.
     */
    public TotpConfig requiresConfirmation(boolean requiresConfirmation) {
        this.requiresConfirmation = requiresConfirmation;
        return this;
    }

    public int secretLength() { return secretLength; }
    public int codeLength() { return codeLength; }
    public int timeStepSeconds() { return timeStepSeconds; }
    public int windowSize() { return windowSize; }
    public String algorithm() { return algorithm; }
    public String issuer() { return issuer; }
    public boolean requiresConfirmation() { return requiresConfirmation; }
}
