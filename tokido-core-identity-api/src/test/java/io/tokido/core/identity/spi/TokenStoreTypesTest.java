package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class TokenStoreTypesTest {

    @Test
    void persistedGrantRejectsBlankHandle() {
        assertThatIllegalArgumentException().isThrownBy(() -> sample(""));
    }

    @Test
    void persistedGrantRejectsNullType() {
        assertThatNullPointerException().isThrownBy(
                () -> new PersistedGrant("h", null, "sub", "client",
                        Set.of("openid"), Instant.now(), Instant.now().plusSeconds(60),
                        null, "{}"));
    }

    @Test
    void persistedGrantAcceptsNullConsumedTime() {
        PersistedGrant g = sample("h-1");
        assertThat(g.consumedTime()).isNull();
    }

    @Test
    void persistedGrantCopiesScopesToImmutable() {
        PersistedGrant g = sample("h-1");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> g.scopes().add("api"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    private PersistedGrant sample(String handle) {
        return new PersistedGrant(
                handle,
                GrantType.AUTHORIZATION_CODE,
                "sub-1",
                "client-1",
                Set.of("openid", "profile"),
                Instant.parse("2026-05-01T00:00:00Z"),
                Instant.parse("2026-05-01T00:10:00Z"),
                null,
                "{\"opaque\":\"data\"}");
    }

    @org.junit.jupiter.api.Nested
    class SmokeContract extends AbstractTokenStoreContract {
        @Override
        protected TokenStore createStore(java.time.Clock clock) {
            java.util.Map<String, PersistedGrant> backing = new java.util.HashMap<>();
            return new TokenStore() {
                @Override
                public void store(PersistedGrant g) {
                    backing.put(g.handle(), g);
                }
                @Override
                public PersistedGrant findByHandle(String h) {
                    PersistedGrant g = backing.get(h);
                    if (g == null) return null;
                    if (!g.expiration().isAfter(clock.instant())) return null; // expired
                    return g;
                }
                @Override
                public void remove(String h) {
                    backing.remove(h);
                }
                @Override
                public void removeAll(String subjectId, String clientId) {
                    backing.entrySet().removeIf(e ->
                            e.getValue().subjectId().equals(subjectId)
                                    && e.getValue().clientId().equals(clientId));
                }
                @Override
                public void removeAll(String subjectId, String clientId, GrantType type) {
                    backing.entrySet().removeIf(e ->
                            e.getValue().subjectId().equals(subjectId)
                                    && e.getValue().clientId().equals(clientId)
                                    && e.getValue().type() == type);
                }
            };
        }
    }
}
