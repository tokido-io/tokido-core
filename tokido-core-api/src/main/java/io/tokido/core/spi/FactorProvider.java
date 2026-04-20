package io.tokido.core.spi;

import io.tokido.core.EnrollmentContext;
import io.tokido.core.EnrollmentResult;
import io.tokido.core.FactorStatus;
import io.tokido.core.VerificationContext;
import io.tokido.core.VerificationResult;

/**
 * Service provider interface for MFA factors.
 * <p>
 * Implement this to add a new factor type (e.g., WebAuthn, email OTP).
 * Register with {@link io.tokido.core.spi.SecretStore} via
 * {@code MfaManager.builder().factor(provider)}.
 *
 * @param <E> the enrollment result type
 * @param <V> the verification result type
 */
public interface FactorProvider<E extends EnrollmentResult, V extends VerificationResult> {

    /**
     * Unique identifier for this factor type (e.g., "totp", "recovery", "webauthn").
     */
    String factorType();

    /**
     * Whether enrollment requires a confirmation step before the factor is active.
     * If true, the user must call {@code MfaManager.confirmEnrollment()} with a valid
     * credential before {@code verify()} will accept credentials for this factor.
     */
    boolean requiresConfirmation();

    /**
     * Enroll a user in this factor. Returns factor-specific enrollment data
     * (e.g., secret URI, QR code, recovery codes).
     * <p>
     * The provider is responsible for generating secrets and passing them to the
     * {@link SecretStore} for persistence.
     */
    E enroll(String userId, EnrollmentContext ctx);

    /**
     * Verify a credential for this factor.
     * <p>
     * The {@link VerificationContext} carries provider-specific properties. Built-in Tokido
     * providers ignore {@link VerificationContext#properties()}; custom implementations should
     * document which keys they read and their types.
     */
    V verify(String userId, String credential, VerificationContext ctx);

    /**
     * Remove a user's enrollment in this factor.
     * Called by the engine before {@link SecretStore#delete}.
     */
    void unenroll(String userId);

    /**
     * Query the enrollment status for a user.
     */
    FactorStatus status(String userId);
}
