package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.util.Objects;
import java.util.Set;

/**
 * RFC 7517 §5 — a JWK Set, returned by the engine's JWKS endpoint.
 *
 * @param keys the keys in the set; non-null
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record JsonWebKeySet(Set<JsonWebKey> keys) {

    public JsonWebKeySet {
        keys = Set.copyOf(Objects.requireNonNull(keys, "keys"));
    }
}
