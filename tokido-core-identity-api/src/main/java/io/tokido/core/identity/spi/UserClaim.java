package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Objects;

/**
 * A single user claim — a {@code (type, value)} pair as emitted in the
 * ID token or at the UserInfo endpoint. The {@code type} is the standard
 * OIDC claim name (e.g., {@code "name"}, {@code "email"}); the {@code value}
 * is the JSON-serialized value as a string.
 *
 * @param type  claim name; non-null and non-blank
 * @param value claim value as a JSON-serializable string; non-null
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record UserClaim(String type, String value) {

    public UserClaim {
        Objects.requireNonNull(type, "type");
        if (type.isBlank()) {
            throw new IllegalArgumentException("type must not be blank");
        }
        Objects.requireNonNull(value, "value");
    }
}
