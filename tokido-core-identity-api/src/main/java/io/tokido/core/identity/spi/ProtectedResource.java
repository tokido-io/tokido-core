package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Objects;
import java.util.Set;

/**
 * An API/protected resource — the audience of access tokens granted scopes
 * defined by this resource.
 *
 * <p>Renamed from Duende's {@code ApiResource} per ADR-0001.
 *
 * @param name        unique resource name (used as access-token audience)
 * @param displayName optional display name for consent UIs
 * @param scopes      the scopes this resource publishes
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record ProtectedResource(String name, String displayName, Set<ResourceScope> scopes) {

    public ProtectedResource {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
    }
}
