package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for any {@link TokenStore} implementation. Subclasses provide
 * a {@link #createStore(Clock)} factory; the {@code clock} is used to compute
 * "is this grant expired?" — implementations that implement expiration via
 * system clock should accept this clock as a fixture.
 */
public abstract class AbstractTokenStoreContract {

    /**
     * Subclass-provided factory.
     *
     * @param clock the clock to use for expiration checks
     * @return an empty TokenStore
     */
    protected abstract TokenStore createStore(Clock clock);

    private static final Instant NOW = Instant.parse("2026-05-01T00:00:00Z");
    private static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);

    private PersistedGrant grant(String handle, String subject, String client,
                                 GrantType type, Instant expiration) {
        return new PersistedGrant(handle, type, subject, client,
                Set.of("openid"), NOW, expiration, null, "{}");
    }

    @Test
    void storeAndFindByHandleRoundTrip() {
        TokenStore store = createStore(FIXED);
        PersistedGrant g = grant("h1", "sub-1", "client-1",
                GrantType.AUTHORIZATION_CODE, NOW.plusSeconds(300));
        store.store(g);
        assertThat(store.findByHandle("h1")).isEqualTo(g);
    }

    @Test
    void findByHandleReturnsNullForUnknown() {
        TokenStore store = createStore(FIXED);
        assertThat(store.findByHandle("nope")).isNull();
    }

    @Test
    void findByHandleReturnsNullForExpiredGrant() {
        TokenStore store = createStore(FIXED);
        store.store(grant("h-expired", "sub-1", "client-1",
                GrantType.REFRESH_TOKEN, NOW.minusSeconds(1)));
        assertThat(store.findByHandle("h-expired")).isNull();
    }

    @Test
    void removeMakesGrantUnreachable() {
        TokenStore store = createStore(FIXED);
        store.store(grant("h1", "sub-1", "client-1",
                GrantType.AUTHORIZATION_CODE, NOW.plusSeconds(300)));
        store.remove("h1");
        assertThat(store.findByHandle("h1")).isNull();
    }

    @Test
    void removeIsNoOpForUnknownHandle() {
        TokenStore store = createStore(FIXED);
        store.remove("nope"); // must not throw
    }

    @Test
    void removeAllForSubjectClientRemovesEverything() {
        TokenStore store = createStore(FIXED);
        store.store(grant("h1", "sub-1", "client-1",
                GrantType.AUTHORIZATION_CODE, NOW.plusSeconds(300)));
        store.store(grant("h2", "sub-1", "client-1",
                GrantType.REFRESH_TOKEN, NOW.plusSeconds(300)));
        store.store(grant("h3", "sub-2", "client-1",
                GrantType.REFRESH_TOKEN, NOW.plusSeconds(300)));
        store.removeAll("sub-1", "client-1");
        assertThat(store.findByHandle("h1")).isNull();
        assertThat(store.findByHandle("h2")).isNull();
        assertThat(store.findByHandle("h3")).isNotNull();
    }

    @Test
    void removeAllForSubjectClientTypeFiltersByType() {
        TokenStore store = createStore(FIXED);
        store.store(grant("h-code", "sub-1", "client-1",
                GrantType.AUTHORIZATION_CODE, NOW.plusSeconds(300)));
        store.store(grant("h-refresh", "sub-1", "client-1",
                GrantType.REFRESH_TOKEN, NOW.plusSeconds(300)));
        store.removeAll("sub-1", "client-1", GrantType.AUTHORIZATION_CODE);
        assertThat(store.findByHandle("h-code")).isNull();
        assertThat(store.findByHandle("h-refresh")).isNotNull();
    }
}
