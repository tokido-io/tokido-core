package io.tokido.core.totp;

/**
 * Thrown when QR code generation fails during TOTP enrollment.
 *
 * <p>Enrollment is aborted before the secret is written to {@link io.tokido.core.spi.SecretStore},
 * so the user remains unenrolled for this factor and {@link #secretUri()} refers only to the URI
 * that QR encoding attempted (for logging or diagnostics).
 */
public final class TotpQrCodeGenerationException extends RuntimeException {
    private final String secretUri;

    public TotpQrCodeGenerationException(String secretUri, Throwable cause) {
        super("Failed to generate QR code for TOTP enrollment", cause);
        this.secretUri = secretUri;
    }

    public String secretUri() {
        return secretUri;
    }
}
