package io.tokido.core;

import java.time.Instant;
import java.util.Map;

/**
 * An audit event emitted by the MFA engine on every state transition.
 *
 * @param userId     the user this event pertains to
 * @param factorType the factor type (e.g., "totp", "recovery")
 * @param action     the action (e.g., "enrolled", "confirmed", "verified", "verification_failed", "unenrolled")
 * @param timestamp  when the event occurred
 * @param metadata   additional context
 */
public record AuditEvent(
        String userId,
        String factorType,
        String action,
        Instant timestamp,
        Map<String, Object> metadata
) {
}
