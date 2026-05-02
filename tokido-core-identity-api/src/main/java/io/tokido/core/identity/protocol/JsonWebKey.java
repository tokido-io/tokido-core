package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;

/**
 * An RFC 7517 JSON Web Key, as a typed wrapper around the wire-format
 * key/value map. Mandatory fields ({@code kty}, {@code kid}) are typed;
 * the rest live in {@code additionalParameters}.
 *
 * <p>The engine never serializes/deserializes JWKs itself — that lives
 * in {@code tokido-core-identity-jwt} (M2).
 *
 * @param kty                  RFC 7517 §4.1 — key type ({@code "RSA"}, {@code "EC"}, etc.); non-null
 * @param kid                  RFC 7517 §4.5 — key id; non-null and non-blank
 * @param use                  RFC 7517 §4.2 — public key use ({@code "sig"}, {@code "enc"}); nullable
 * @param alg                  RFC 7517 §4.4 — intended algorithm; nullable
 * @param additionalParameters all other JWK fields (n, e, x, y, crv, ...); non-null
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record JsonWebKey(String kty, String kid, String use, String alg,
                         Map<String, Object> additionalParameters) {

    public JsonWebKey {
        Objects.requireNonNull(kty, "kty");
        Objects.requireNonNull(kid, "kid");
        if (kid.isBlank()) {
            throw new IllegalArgumentException("kid must not be blank");
        }
        additionalParameters = Map.copyOf(
                Objects.requireNonNull(additionalParameters, "additionalParameters"));
    }
}
