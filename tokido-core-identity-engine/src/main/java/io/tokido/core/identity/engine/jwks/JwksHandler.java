package io.tokido.core.identity.engine.jwks;

import io.tokido.core.identity.key.JwksKeyRenderer;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SigningKey;
import io.tokido.core.identity.protocol.JsonWebKey;
import io.tokido.core.identity.protocol.JsonWebKeySet;
import org.apiguardian.api.API;

import java.util.HashSet;
import java.util.Set;

/**
 * Builds the JWKS document from {@link KeyStore#allKeys()}.
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2")
public final class JwksHandler {

    private final KeyStore keyStore;
    private final JwksKeyRenderer renderer;

    public JwksHandler(KeyStore keyStore, JwksKeyRenderer renderer) {
        this.keyStore = keyStore;
        this.renderer = renderer;
    }

    public JsonWebKeySet build() {
        Set<JsonWebKey> jwks = new HashSet<>();
        for (SigningKey k : keyStore.allKeys()) {
            jwks.add(renderer.render(k));
        }
        return new JsonWebKeySet(Set.copyOf(jwks));
    }
}
