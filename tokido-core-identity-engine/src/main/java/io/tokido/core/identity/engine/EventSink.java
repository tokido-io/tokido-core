package io.tokido.core.identity.engine;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Map;

/**
 * Optional audit hook. The engine emits a structured event per significant
 * lifecycle action (token issued, token revoked, consent granted, broker
 * callback, etc.). Implementations may forward to logs, metrics, audit
 * pipelines, or a no-op.
 *
 * <p>The default implementation in {@link #noop()} discards every event.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface EventSink {

    /**
     * Emit one event. Implementations must not block the engine for long.
     *
     * @param type       event type (e.g., {@code "token.issued"})
     * @param timestamp  when the event occurred
     * @param attributes additional event attributes
     */
    void emit(String type, Instant timestamp, Map<String, Object> attributes);

    /**
     * No-op sink used by default when no sink is supplied.
     *
     * @return a sink that drops every event
     */
    static EventSink noop() {
        return (type, timestamp, attributes) -> { /* drop */ };
    }
}
