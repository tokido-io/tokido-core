package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Objects;

/**
 * A scope offered by a {@link ProtectedResource}. The wire-protocol scope name
 * is the {@code name} field; consent UIs may use {@code displayName}.
 *
 * <p>Renamed from Duende's {@code ApiScope} per ADR-0001.
 *
 * @param name        wire-protocol scope name; non-null, non-blank
 * @param displayName optional display name; nullable
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record ResourceScope(String name, String displayName) {

    public ResourceScope {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
    }
}
