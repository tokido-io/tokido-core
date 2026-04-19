package io.tokido.core.totp;

import io.tokido.core.VerificationResult;

/**
 * Result of TOTP code verification.
 *
 * @param valid  whether the code was accepted
 * @param reason null on success; "invalid" for wrong code, "replay" for reused code
 */
public record TotpVerificationResult(boolean valid, String reason) implements VerificationResult {
    @Override
    public java.util.Optional<String> failureReason() {
        return java.util.Optional.ofNullable(reason);
    }
}
