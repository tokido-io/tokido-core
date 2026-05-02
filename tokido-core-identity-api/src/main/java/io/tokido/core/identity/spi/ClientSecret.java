package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Objects;

/**
 * A hashed client secret. The {@code value} is implementation-defined
 * (e.g., bcrypt-encoded) — the engine treats it as opaque and only the
 * {@link io.tokido.core.identity.engine.IdentityEngine} compares submitted
 * credentials by delegating to a hashing strategy.
 *
 * @param value       opaque hashed secret; non-null
 * @param description optional human-readable description; nullable
 * @param expiration  optional expiration; null means "never expires"
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record ClientSecret(String value, String description, Instant expiration) {

    public ClientSecret {
        Objects.requireNonNull(value, "value");
    }
}
