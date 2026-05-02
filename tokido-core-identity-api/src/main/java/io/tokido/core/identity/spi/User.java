package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;

/**
 * A user account known to the OIDC engine.
 *
 * @param subjectId immutable identifier (the {@code sub} claim); non-null and non-blank
 * @param username  human-readable username (login name); non-null
 * @param enabled   if false, all flows for this user are rejected
 * @param profile   additional profile attributes (read-only key/value);
 *                  separate from {@link UserClaim} which is the wire-format
 *                  emitted in tokens
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record User(String subjectId, String username, boolean enabled, Map<String, Object> profile) {

    public User {
        Objects.requireNonNull(subjectId, "subjectId");
        if (subjectId.isBlank()) {
            throw new IllegalArgumentException("subjectId must not be blank");
        }
        Objects.requireNonNull(username, "username");
        profile = Map.copyOf(Objects.requireNonNull(profile, "profile"));
    }
}
