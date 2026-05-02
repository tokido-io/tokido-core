package io.tokido.core.identity.key;

import io.tokido.core.identity.protocol.JsonWebKey;
import org.apiguardian.api.API;

/**
 * SPI for converting a {@link SigningKey} to a public-only {@link JsonWebKey}
 * for the JWKS endpoint. The engine calls this once per key returned from
 * {@link KeyStore#allKeys()}. Implemented by {@code JwksRenderer} in
 * {@code tokido-core-identity-jwt} (M2.RC1).
 *
 * <p>Lives in identity-api (rather than identity-engine) because it operates
 * on key types from this module and produces a wire-format type from this
 * module — no engine semantics involved. Adding it here is an additive M2
 * change, not a break to the M1 lock.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public interface JwksKeyRenderer {
    /**
     * @param key the signing key
     * @return public-only JWK
     */
    JsonWebKey render(SigningKey key);
}
