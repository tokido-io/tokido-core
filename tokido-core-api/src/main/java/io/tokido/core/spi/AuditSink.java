package io.tokido.core.spi;

import io.tokido.core.AuditEvent;

/**
 * Receives audit events from the MFA engine.
 * <p>
 * Implementations might log to a file, publish to a message queue, or store in a database.
 * The default no-op implementation silently discards events.
 */
public interface AuditSink {

    void emit(AuditEvent event);

    static AuditSink noop() {
        return event -> {};
    }
}
