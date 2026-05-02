package io.tokido.core.identity.engine;

import io.tokido.core.identity.key.SigningKey;
import org.apiguardian.api.API;

/**
 * SPI for signing JWS-protected payloads. The engine emits payloads as
 * JSON-serialized strings; the signer wraps them in a compact-serialization
 * JWS using the provided {@link SigningKey}.
 *
 * <p>Implemented by {@code NimbusTokenSigner} in {@code tokido-core-identity-jwt}
 * (M2). The engine module never directly imports any JWT library — it talks
 * to this SPI.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface TokenSigner {

    /**
     * Sign {@code payload} with {@code key} and return the compact JWS.
     *
     * @param payload the payload to sign (typically JSON)
     * @param key     the signing key to use
     * @return the compact-serialized JWS
     * @throws IllegalStateException if the key cannot be used (state RETIRED, alg mismatch, etc.)
     */
    String sign(String payload, SigningKey key);
}
