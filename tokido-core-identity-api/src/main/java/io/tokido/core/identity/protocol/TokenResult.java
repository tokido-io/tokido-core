package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/** Outcome of {@code IdentityEngine.token}. */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public sealed interface TokenResult permits TokenResult.Success, TokenResult.Error {

    /**
     * Successful token response (RFC 6749 §5.1 / OIDC Core §3.1.3.3).
     *
     * @param accessToken  issued access token; non-null
     * @param tokenType    token type ({@code "Bearer"}); non-null
     * @param expiresIn    access-token lifetime; non-null
     * @param refreshToken issued refresh token; nullable (not issued for client_credentials)
     * @param idToken      issued ID token; nullable (not issued without {@code openid} scope)
     * @param scope        granted scopes; non-null
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Success(String accessToken,
                   String tokenType,
                   Duration expiresIn,
                   String refreshToken,
                   String idToken,
                   Set<String> scope) implements TokenResult {
        public Success {
            Objects.requireNonNull(accessToken, "accessToken");
            Objects.requireNonNull(tokenType, "tokenType");
            Objects.requireNonNull(expiresIn, "expiresIn");
            scope = Set.copyOf(Objects.requireNonNull(scope, "scope"));
        }
    }

    /**
     * Error response (RFC 6749 §5.2).
     *
     * @param code        wire error code; non-null and non-blank
     * @param description optional human-readable description; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Error(String code, String description) implements TokenResult {
        public Error {
            Objects.requireNonNull(code, "code");
            if (code.isBlank()) {
                throw new IllegalArgumentException("code must not be blank");
            }
        }
    }
}
