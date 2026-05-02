package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for any {@link ClientStore} implementation. Subclasses
 * provide a {@link #createStore(Set)} factory that returns a store
 * seeded with the given clients.
 */
public abstract class AbstractClientStoreContract {

    protected abstract ClientStore createStore(Set<Client> clients);

    private Client sample(String id) {
        return new Client(
                id,
                Set.of(new ClientSecret("hashed:abc", null, null)),
                Set.of("https://app/cb"),
                Set.of(),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                true,
                false,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                true);
    }

    @Test
    void findByIdReturnsSeededClient() {
        Client c = sample("c1");
        ClientStore store = createStore(Set.of(c));
        assertThat(store.findById("c1")).isEqualTo(c);
    }

    @Test
    void findByIdReturnsNullForUnknown() {
        ClientStore store = createStore(Set.of(sample("c1")));
        assertThat(store.findById("nope")).isNull();
    }

    @Test
    void existsTrueForKnown() {
        ClientStore store = createStore(Set.of(sample("c1")));
        assertThat(store.exists("c1")).isTrue();
    }

    @Test
    void existsFalseForUnknown() {
        ClientStore store = createStore(Set.of(sample("c1")));
        assertThat(store.exists("nope")).isFalse();
    }

    @Test
    void findByIdReturnsDistinctClients() {
        Client a = sample("a");
        Client b = sample("b");
        ClientStore store = createStore(Set.of(a, b));
        assertThat(store.findById("a")).isEqualTo(a);
        assertThat(store.findById("b")).isEqualTo(b);
    }
}
