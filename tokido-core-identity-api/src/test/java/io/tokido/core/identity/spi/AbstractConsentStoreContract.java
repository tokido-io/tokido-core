package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for any {@link ConsentStore} implementation. Subclasses
 * provide a {@link #createStore()} factory that returns an empty store.
 */
public abstract class AbstractConsentStoreContract {

    protected abstract ConsentStore createStore();

    private Consent sample(String subject, String client) {
        return new Consent(subject, client, Set.of("openid"),
                Instant.parse("2026-08-01T00:00:00Z"));
    }

    @Test
    void findReturnsNullForUnknownKey() {
        ConsentStore store = createStore();
        assertThat(store.find("sub", "client")).isNull();
    }

    @Test
    void storeAndFindRoundTrip() {
        ConsentStore store = createStore();
        Consent c = sample("sub-1", "client-1");
        store.store(c);
        assertThat(store.find("sub-1", "client-1")).isEqualTo(c);
    }

    @Test
    void storeReplacesPriorConsent() {
        ConsentStore store = createStore();
        Consent first = new Consent("sub-1", "client-1", Set.of("openid"),
                Instant.parse("2026-06-01T00:00:00Z"));
        Consent second = new Consent("sub-1", "client-1", Set.of("openid", "profile"),
                Instant.parse("2026-09-01T00:00:00Z"));
        store.store(first);
        store.store(second);
        assertThat(store.find("sub-1", "client-1")).isEqualTo(second);
    }

    @Test
    void removeMakesConsentUnreachable() {
        ConsentStore store = createStore();
        store.store(sample("sub-1", "client-1"));
        store.remove("sub-1", "client-1");
        assertThat(store.find("sub-1", "client-1")).isNull();
    }

    @Test
    void removeIsNoOpForUnknownKey() {
        ConsentStore store = createStore();
        store.remove("nope", "nope"); // must not throw
    }
}
