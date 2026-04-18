package io.tokido.core.recovery;

import io.tokido.core.EnrollmentResult;

import java.util.List;

/**
 * Result of recovery code enrollment.
 * The plaintext codes are returned once and must be shown to the user immediately.
 *
 * @param codes plaintext recovery codes (never stored — only bcrypt hashes are persisted)
 */
public record RecoveryEnrollmentResult(List<String> codes) implements EnrollmentResult {
}
