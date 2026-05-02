package io.tokido.core.identity.protocol;

import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * OAuth 2.0 / OIDC token endpoint request (RFC 6749 §3.2 / OIDC Core §3.1.3).
 *
 * @param grantType    grant type wire string (e.g., {@code "authorization_code"}); non-null and non-blank
 * @param clientId     client id; non-null and non-blank
 * @param clientSecret submitted client secret (for client_secret_post / client_secret_basic); nullable
 * @param authMethod   how the client authenticated; non-null
 * @param code         authorization code (for authorization_code grant); nullable
 * @param redirectUri  redirect_uri (must match the authorize request); nullable
 * @param codeVerifier PKCE code_verifier; nullable
 * @param refreshToken refresh token (for refresh_token grant); nullable
 * @param scopes       requested scopes (for refresh / client_credentials); null becomes empty
 * @param additional   additional adapter-supplied parameters; null becomes empty map
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record TokenRequest(
        String grantType,
        String clientId,
        String clientSecret,
        ClientAuthenticationMethod authMethod,
        String code,
        String redirectUri,
        String codeVerifier,
        String refreshToken,
        Set<String> scopes,
        Map<String, String> additional) {

    public TokenRequest {
        Objects.requireNonNull(grantType, "grantType");
        if (grantType.isBlank()) {
            throw new IllegalArgumentException("grantType must not be blank");
        }
        Objects.requireNonNull(clientId, "clientId");
        if (clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        Objects.requireNonNull(authMethod, "authMethod");
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        additional = additional == null ? Map.of() : Map.copyOf(additional);
    }
}
