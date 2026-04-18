package io.tokido.core.test;

import io.tokido.core.AuditEvent;
import io.tokido.core.spi.AuditSink;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * An {@link AuditSink} that collects all emitted events for test assertions.
 * Thread-safe via {@link CopyOnWriteArrayList}.
 */
public class CollectingAuditSink implements AuditSink {

    private final List<AuditEvent> events = new CopyOnWriteArrayList<>();

    @Override
    public void emit(AuditEvent event) {
        events.add(event);
    }

    public List<AuditEvent> events() {
        return List.copyOf(events);
    }

    public List<AuditEvent> eventsFor(String userId) {
        return events.stream()
                .filter(e -> e.userId().equals(userId))
                .toList();
    }

    public List<AuditEvent> eventsFor(String userId, String action) {
        return events.stream()
                .filter(e -> e.userId().equals(userId) && e.action().equals(action))
                .toList();
    }

    public AuditEvent lastEvent() {
        if (events.isEmpty()) {
            throw new IllegalStateException("No audit events emitted");
        }
        return events.getLast();
    }

    public int size() {
        return events.size();
    }

    public void clear() {
        events.clear();
    }
}
