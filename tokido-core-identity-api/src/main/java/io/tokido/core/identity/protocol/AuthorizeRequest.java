package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * OIDC authorize request. Maps roughly 1:1 with the OAuth 2.0 / OIDC
 * authorize endpoint query parameters (RFC 6749 §4.1.1, OIDC Core §3.1.2).
 * Framework adapters parse the incoming HTTP request and build this record;
 * the engine consumes it.
 *
 * <p>Nullability: all object fields are nullable except {@code clientId}
 * (must be non-blank). Engine handlers validate semantics (presence-when-
 * required, length, charset) and emit {@link AuthorizeResult.Error} on bad
 * input.
 *
 * @param clientId            client identifier; non-null and non-blank
 * @param responseType        OAuth response_type; nullable, validated by engine
 * @param redirectUri         redirect_uri; nullable
 * @param scopes              requested scopes; null becomes empty set
 * @param state               opaque state for CSRF protection; nullable
 * @param nonce               OIDC nonce; nullable
 * @param codeChallenge       PKCE code_challenge; nullable
 * @param codeChallengeMethod PKCE code_challenge_method ({@code "plain"}, {@code "S256"}); nullable
 * @param responseMode        response_mode ({@code "query"}, {@code "fragment"}, {@code "form_post"}); nullable
 * @param acrValues           requested ACR values; null becomes empty set
 * @param maxAge              max age for re-authentication, in seconds; nullable
 * @param prompt              OIDC prompt parameter ({@code "none"}, {@code "login"}, ...); nullable
 * @param loginHint           OIDC login_hint; nullable
 * @param uiLocales           OIDC ui_locales; nullable
 * @param additional          additional adapter-supplied parameters; null becomes empty map
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record AuthorizeRequest(
        String clientId,
        String responseType,
        String redirectUri,
        Set<String> scopes,
        String state,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod,
        String responseMode,
        Set<String> acrValues,
        Long maxAge,
        String prompt,
        String loginHint,
        String uiLocales,
        Map<String, String> additional) {

    public AuthorizeRequest {
        Objects.requireNonNull(clientId, "clientId");
        if (clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        acrValues = acrValues == null ? Set.of() : Set.copyOf(acrValues);
        additional = additional == null ? Map.of() : Map.copyOf(additional);
    }
}
