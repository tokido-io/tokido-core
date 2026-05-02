package io.tokido.core.identity.engine.jwks;

import io.tokido.core.identity.key.JwksKeyRenderer;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import io.tokido.core.identity.protocol.JsonWebKey;
import io.tokido.core.identity.protocol.JsonWebKeySet;
import io.tokido.core.test.identity.MapKeyStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-test for {@link JwksHandler}. Uses an inline stub {@link JwksKeyRenderer}
 * rather than identity-jwt's real {@code JwksRenderer} to avoid a reactor
 * cycle (identity-jwt depends on identity-engine at compile scope for
 * TokenSigner). Real-renderer integration testing is done in the
 * tokido-core-identity-conformance module at M2.RC1 Task 21.
 */
class JwksHandlerTest {

    @Test
    void buildsJwksByRenderingEachKey() {
        SigningKey k1 = sample("kid-1");
        SigningKey k2 = sample("kid-2");
        JwksKeyRenderer rendererStub = key ->
                new JsonWebKey("RSA", key.kid(), "sig", "RS256", Map.of("n", "modulus", "e", "AQAB"));

        JsonWebKeySet jwks = new JwksHandler(new MapKeyStore(Set.of(k1, k2)), rendererStub).build();

        assertThat(jwks.keys()).hasSize(2);
        assertThat(jwks.keys()).extracting(JsonWebKey::kid)
                .containsExactlyInAnyOrder("kid-1", "kid-2");
    }

    @Test
    void emptyKeyStoreProducesEmptyJwks() {
        JwksKeyRenderer rendererStub = key -> {
            throw new AssertionError("renderer should not be called for empty store");
        };
        JsonWebKeySet jwks = new JwksHandler(new MapKeyStore(Set.of()), rendererStub).build();
        assertThat(jwks.keys()).isEmpty();
    }

    private SigningKey sample(String kid) {
        return new SigningKey(kid, SignatureAlgorithm.RS256,
                new KeyMaterial(new byte[]{1, 2, 3}, SignatureAlgorithm.RS256),
                KeyState.ACTIVE,
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"));
    }
}
