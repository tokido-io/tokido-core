package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class ClientStoreTypesTest {

    @Test
    void clientSecretRejectsNullValue() {
        assertThatNullPointerException().isThrownBy(
                () -> new ClientSecret(null, "desc", null));
    }

    @Test
    void clientSecretAcceptsNullExpiration() {
        ClientSecret s = new ClientSecret("hashed:abc", "primary", null);
        assertThat(s.value()).isEqualTo("hashed:abc");
        assertThat(s.expiration()).isNull();
    }

    @Test
    void clientRejectsNullClientId() {
        assertThatNullPointerException().isThrownBy(() -> sampleClient(null));
    }

    @Test
    void clientRejectsBlankClientId() {
        assertThatIllegalArgumentException().isThrownBy(() -> sampleClient(""));
    }

    @Test
    void clientReturnsImmutableCollections() {
        Client c = sampleClient("c1");
        assertThat(c.redirectUris()).containsExactly("https://app/cb");
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> c.redirectUris().add("https://other/cb"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    private Client sampleClient(String id) {
        return new Client(
                id,
                Set.of(new ClientSecret("hashed:abc", "primary", null)),
                Set.of("https://app/cb"),
                Set.of("https://app/post-logout"),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                true,
                true,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                true);
    }

    @org.junit.jupiter.api.Nested
    class SmokeContract extends AbstractClientStoreContract {
        @Override
        protected ClientStore createStore(java.util.Set<Client> clients) {
            java.util.Map<String, Client> byId = new java.util.HashMap<>();
            for (Client c : clients) byId.put(c.clientId(), c);
            java.util.Map<String, Client> snapshot = java.util.Map.copyOf(byId);
            return new ClientStore() {
                @Override public Client findById(String id) { return snapshot.get(id); }
                @Override public boolean exists(String id) { return snapshot.containsKey(id); }
            };
        }
    }
}
