package io.tokido.core.recovery;

import io.tokido.core.VerificationResult;

/**
 * Result of recovery code verification.
 *
 * @param valid          whether the code was accepted
 * @param codesRemaining number of unused recovery codes remaining after this verification
 */
public record RecoveryVerificationResult(boolean valid, int codesRemaining) implements VerificationResult {
}
