package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Objects;
import java.util.Set;

/**
 * An OIDC identity scope (e.g., {@code openid}, {@code profile}, {@code email}).
 * Identity scopes drive the claims emitted in the ID token and at the UserInfo
 * endpoint.
 *
 * <p>Renamed from Duende's {@code IdentityResource} per ADR-0001 to avoid
 * licensing/copyright entanglement with the Duende product family.
 *
 * @param name           wire-protocol scope name; non-null, non-blank
 * @param displayName    optional display name for consent UIs; nullable
 * @param userClaimNames claim names this scope unlocks in the ID token / userinfo
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record IdentityScope(String name, String displayName, Set<String> userClaimNames) {

    public IdentityScope {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        userClaimNames = Set.copyOf(Objects.requireNonNull(userClaimNames, "userClaimNames"));
    }
}
