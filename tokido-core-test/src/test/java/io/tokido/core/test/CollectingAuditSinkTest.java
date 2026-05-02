package io.tokido.core.test;

import io.tokido.core.AuditEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CollectingAuditSinkTest {

    private AuditEvent event(String userId, String action) {
        return new AuditEvent(userId, "totp", action, Instant.now(), Map.of());
    }

    @Test
    void emitAndEventsRoundTrip() {
        CollectingAuditSink sink = new CollectingAuditSink();
        AuditEvent e = event("alice", "login");
        sink.emit(e);
        assertThat(sink.events()).containsExactly(e);
    }

    @Test
    void eventsForUserFilters() {
        CollectingAuditSink sink = new CollectingAuditSink();
        AuditEvent alice = event("alice", "login");
        AuditEvent bob = event("bob", "login");
        sink.emit(alice);
        sink.emit(bob);
        assertThat(sink.eventsFor("alice")).containsExactly(alice);
    }

    @Test
    void eventsForUserAndActionFilters() {
        CollectingAuditSink sink = new CollectingAuditSink();
        AuditEvent login = event("alice", "login");
        AuditEvent logout = event("alice", "logout");
        sink.emit(login);
        sink.emit(logout);
        assertThat(sink.eventsFor("alice", "login")).containsExactly(login);
    }

    @Test
    void lastEventReturnsLastEmitted() {
        CollectingAuditSink sink = new CollectingAuditSink();
        AuditEvent first = event("alice", "login");
        AuditEvent second = event("alice", "logout");
        sink.emit(first);
        sink.emit(second);
        assertThat(sink.lastEvent()).isEqualTo(second);
    }

    @Test
    void lastEventThrowsWhenEmpty() {
        CollectingAuditSink sink = new CollectingAuditSink();
        assertThatThrownBy(sink::lastEvent).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void sizeReflectsEmittedCount() {
        CollectingAuditSink sink = new CollectingAuditSink();
        sink.emit(event("alice", "login"));
        sink.emit(event("alice", "logout"));
        assertThat(sink.size()).isEqualTo(2);
    }

    @Test
    void clearRemovesAllEvents() {
        CollectingAuditSink sink = new CollectingAuditSink();
        sink.emit(event("alice", "login"));
        sink.clear();
        assertThat(sink.events()).isEmpty();
        assertThat(sink.size()).isZero();
    }
}
