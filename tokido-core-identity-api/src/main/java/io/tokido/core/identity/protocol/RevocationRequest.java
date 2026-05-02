package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.util.Objects;

/**
 * RFC 7009 token revocation request.
 *
 * @param token         the token to revoke; non-null and non-blank
 * @param tokenTypeHint optional hint ({@code "access_token"}, {@code "refresh_token"}); nullable
 * @param clientId      authenticated calling client id; non-null
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record RevocationRequest(String token, String tokenTypeHint, String clientId) {

    public RevocationRequest {
        Objects.requireNonNull(token, "token");
        if (token.isBlank()) {
            throw new IllegalArgumentException("token must not be blank");
        }
        Objects.requireNonNull(clientId, "clientId");
    }
}
