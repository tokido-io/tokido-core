package io.tokido.core.identity.engine.authorize;

import io.tokido.core.identity.protocol.AuthenticationState;
import io.tokido.core.identity.protocol.AuthorizeRequest;
import io.tokido.core.identity.protocol.AuthorizeResult;
import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientStore;
import io.tokido.core.identity.spi.Consent;
import io.tokido.core.identity.spi.ConsentStore;
import io.tokido.core.identity.spi.GrantType;
import io.tokido.core.identity.spi.PersistedGrant;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.TokenStore;
import org.apiguardian.api.API;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Drives the OIDC {@code /authorize} endpoint, happy-path only at Task 16.
 *
 * <p>Validation gates that fail (unknown client, bad redirect URI, unsupported
 * scope, missing PKCE, missing login, missing consent) currently throw
 * {@link IllegalStateException} with a message tagging the gate; Task 17
 * replaces those with proper {@link AuthorizeResult.Error} /
 * {@link AuthorizeResult.LoginRequired} / {@link AuthorizeResult.ConsentRequired}
 * variants.
 *
 * <p>Happy-path output: a {@link AuthorizeResult.Redirect} carrying
 * {@code code} (and optionally {@code state}, {@code iss}) in its params map,
 * plus a constructed redirect URI of the form
 * {@code redirect_uri?code=...&state=...&iss=...}. The persisted artefact is
 * a {@link PersistedGrant} of type {@link GrantType#AUTHORIZATION_CODE} whose
 * {@code data} field is the JSON serialization of an
 * {@link AuthorizationCodeData}.
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2")
public final class AuthorizeHandler {

    /** Default authorization code lifetime per OIDC Core (10 minutes is the SHOULD). */
    public static final Duration AUTHORIZATION_CODE_LIFETIME = Duration.ofMinutes(10);

    /** Authorization code entropy: 32 bytes Base64url-encoded → 43 chars, no padding. */
    private static final int CODE_BYTE_LENGTH = 32;

    private static final SecureRandom RNG = new SecureRandom();

    private final URI issuer;
    private final Clock clock;
    private final ClientStore clientStore;
    private final ConsentStore consentStore;
    private final ResourceStore resourceStore;
    private final TokenStore tokenStore;

    public AuthorizeHandler(URI issuer,
                            Clock clock,
                            ClientStore clientStore,
                            ConsentStore consentStore,
                            ResourceStore resourceStore,
                            TokenStore tokenStore) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.clientStore = Objects.requireNonNull(clientStore, "clientStore");
        this.consentStore = Objects.requireNonNull(consentStore, "consentStore");
        this.resourceStore = Objects.requireNonNull(resourceStore, "resourceStore");
        this.tokenStore = Objects.requireNonNull(tokenStore, "tokenStore");
    }

    /**
     * Run the happy-path authorize flow.
     *
     * @param req   incoming request
     * @param state browser-session auth state
     * @return a {@link AuthorizeResult.Redirect} carrying the issued code
     * @throws IllegalStateException for any branch the plan defers to Task 17
     */
    public AuthorizeResult handle(AuthorizeRequest req, AuthenticationState state) {
        Objects.requireNonNull(req, "req");
        Objects.requireNonNull(state, "state");

        // 1. Resolve client.
        Client client = clientStore.findById(req.clientId());
        if (client == null || !client.enabled()) {
            throw new IllegalStateException("invalid_client (handled in task 17)");
        }

        // 2. Validate redirect URI.
        if (!RedirectUriMatcher.matches(req.redirectUri(), client.redirectUris())) {
            throw new IllegalStateException("invalid redirect_uri (handled in task 17)");
        }

        // 3. Filter scopes.
        Set<String> scopes;
        try {
            scopes = ScopeFilter.filter(req.scopes(), client.allowedScopes());
        } catch (ScopeFilter.UnsupportedScopeException e) {
            throw new IllegalStateException("invalid_scope (handled in task 17)", e);
        }
        // resourceStore is not consulted at Task 16 (Task 17/18 will filter
        // identity scopes against ResourceStore). The dependency is still
        // injected so the upgrade lands without re-wiring.

        // 4. Validate response_type == "code".
        if (!"code".equals(req.responseType())) {
            throw new IllegalStateException("unsupported_response_type (handled in task 17)");
        }

        // 5. PKCE required?
        if (client.requirePkce() && (req.codeChallenge() == null || req.codeChallenge().isBlank())) {
            throw new IllegalStateException("invalid_request: PKCE required (handled in task 17)");
        }

        // 6. Login required?
        if (state.subjectId() == null) {
            throw new IllegalStateException("login_required (handled in task 17)");
        }

        // 7. Consent required?
        Consent consent = consentStore.find(state.subjectId(), client.clientId());
        if (consent == null || !consent.scopes().containsAll(scopes)) {
            throw new IllegalStateException("consent_required (handled in task 17)");
        }

        // 8. Generate code, build the data payload, persist.
        String code = generateCode();
        AuthorizationCodeData data = new AuthorizationCodeData(
                req.nonce(),
                req.codeChallenge(),
                req.codeChallengeMethod(),
                scopes,
                req.redirectUri(),
                state.authenticatedAt(),
                state.acr());
        Instant now = clock.instant();
        PersistedGrant grant = new PersistedGrant(
                code,
                GrantType.AUTHORIZATION_CODE,
                state.subjectId(),
                client.clientId(),
                scopes,
                now,
                now.plus(AUTHORIZATION_CODE_LIFETIME),
                null,
                data.toJson());
        tokenStore.store(grant);

        // 9. Build redirect.
        Map<String, String> params = new LinkedHashMap<>();
        params.put("code", code);
        if (req.state() != null) {
            params.put("state", req.state());
        }
        params.put("iss", issuer.toString());
        URI redirect = appendQuery(req.redirectUri(), params);
        return new AuthorizeResult.Redirect(redirect, params);
    }

    /** 32 bytes of {@link SecureRandom} entropy, Base64url, no padding. */
    private static String generateCode() {
        byte[] bytes = new byte[CODE_BYTE_LENGTH];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Append the params as a query string to {@code base}, picking
     * {@code '?'} or {@code '&'} based on whether {@code base} already has
     * a query.
     */
    private static URI appendQuery(String base, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(base);
        char sep = base.indexOf('?') < 0 ? '?' : '&';
        for (Map.Entry<String, String> e : params.entrySet()) {
            sb.append(sep);
            sb.append(urlEncode(e.getKey()));
            sb.append('=');
            sb.append(urlEncode(e.getValue()));
            sep = '&';
        }
        return URI.create(sb.toString());
    }

    /** Application/x-www-form-urlencoded encoding, sufficient for our token-shaped values. */
    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
