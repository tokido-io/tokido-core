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
 * Drives the OIDC {@code /authorize} endpoint.
 *
 * <p>Returns one of the {@link AuthorizeResult} variants depending on which
 * validation gate fails (or succeeds):
 * <ul>
 *   <li>{@link AuthorizeResult.Redirect} for the happy path — carries
 *       {@code code} (and optionally {@code state}, {@code iss}) in its
 *       params map, plus a constructed redirect URI of the form
 *       {@code redirect_uri?code=...&state=...&iss=...}. The persisted
 *       artefact is a {@link PersistedGrant} of type
 *       {@link GrantType#AUTHORIZATION_CODE} whose {@code data} field is
 *       the JSON serialization of an {@link AuthorizationCodeData}.</li>
 *   <li>{@link AuthorizeResult.Error} with code {@code invalid_client},
 *       {@code invalid_request}, {@code invalid_scope},
 *       {@code unsupported_response_type}, or — when {@code prompt=none} is
 *       set and the end-user cannot proceed silently — {@code login_required}
 *       / {@code consent_required} per OIDC Core §3.1.2.1.</li>
 *   <li>{@link AuthorizeResult.LoginRequired} when the session is
 *       anonymous and {@code prompt=none} was not requested.</li>
 *   <li>{@link AuthorizeResult.ConsentRequired} when stored consent is
 *       missing or doesn't cover all requested scopes and {@code prompt=none}
 *       was not requested.</li>
 * </ul>
 *
 * <p>Per RFC 6749 §4.1.2.1, when {@code redirect_uri} fails validation the
 * authorization server must NOT redirect to the supplied URI and must NOT
 * echo {@code state} back. The {@code Error} returned for that branch carries
 * {@code state == null}; the framework adapter is expected to render the
 * error directly (e.g., as a 400 page) instead of redirecting. Errors that
 * happen after {@code redirect_uri} is validated do echo {@code state} so
 * the adapter can attach it to the redirect response. {@code MfaRequired} is
 * deferred to M4.
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
     * Run the authorize flow.
     *
     * @param req   incoming request
     * @param state browser-session auth state
     * @return one of the {@link AuthorizeResult} variants — see the class
     *         javadoc for the mapping from gate to variant
     */
    public AuthorizeResult handle(AuthorizeRequest req, AuthenticationState state) {
        Objects.requireNonNull(req, "req");
        Objects.requireNonNull(state, "state");

        // 1. Resolve client.
        Client client = clientStore.findById(req.clientId());
        if (client == null) {
            return new AuthorizeResult.Error(
                    "invalid_client", "unknown client: " + req.clientId(), req.state());
        }
        if (!client.enabled()) {
            return new AuthorizeResult.Error(
                    "invalid_client", "client is disabled", req.state());
        }

        // 2. Validate redirect URI.
        // Per RFC 6749 §4.1.2.1, a redirect_uri mismatch must NOT redirect to
        // the supplied URI and must NOT echo `state`. We pass null for state.
        if (!RedirectUriMatcher.matches(req.redirectUri(), client.redirectUris())) {
            return new AuthorizeResult.Error(
                    "invalid_request",
                    "redirect_uri does not match a registered URI",
                    null);
        }

        // 3. Filter scopes.
        Set<String> scopes;
        try {
            scopes = ScopeFilter.filter(req.scopes(), client.allowedScopes());
        } catch (ScopeFilter.UnsupportedScopeException e) {
            return new AuthorizeResult.Error(
                    "invalid_scope", "scope not allowed: " + e.scope(), req.state());
        }
        // resourceStore is not consulted at Task 17 (Task 18 will filter
        // identity scopes against ResourceStore). The dependency is still
        // injected so the upgrade lands without re-wiring.

        // 4. Validate response_type == "code".
        if (!"code".equals(req.responseType())) {
            return new AuthorizeResult.Error(
                    "unsupported_response_type",
                    "response_type must be \"code\"",
                    req.state());
        }

        // 4b. Client allowed to use the authorization_code grant?
        // Per RFC 6749 §5.2 unauthorized_client = "the authenticated client
        // is not authorized to use this authorization grant type". RC1 only
        // supports the code grant, so the only meaningful gate here is that
        // AUTHORIZATION_CODE is in client.allowedGrantTypes.
        if (!client.allowedGrantTypes().contains(GrantType.AUTHORIZATION_CODE)) {
            return new AuthorizeResult.Error(
                    "unauthorized_client",
                    "client not allowed to use authorization_code grant",
                    req.state());
        }

        // 5. PKCE required?
        if (client.requirePkce() && (req.codeChallenge() == null || req.codeChallenge().isBlank())) {
            return new AuthorizeResult.Error(
                    "invalid_request", "code_challenge required", req.state());
        }

        // 6. Login required? Per OIDC Core §3.1.2.1, prompt=none mandates an
        // error rather than a login UI when the end-user is not authenticated.
        boolean promptNone = promptContains(req.prompt(), "none");
        if (state.subjectId() == null) {
            if (promptNone) {
                return new AuthorizeResult.Error(
                        "login_required",
                        "prompt=none but end-user is not authenticated",
                        req.state());
            }
            return new AuthorizeResult.LoginRequired(null);
        }

        // 7. Consent required? Per OIDC Core §3.1.2.1, prompt=none also turns
        // a missing/insufficient consent into a consent_required error
        // instead of a consent UI.
        Consent consent = consentStore.find(state.subjectId(), client.clientId());
        if (consent == null || !consent.scopes().containsAll(scopes)) {
            if (promptNone) {
                return new AuthorizeResult.Error(
                        "consent_required",
                        "prompt=none but end-user has not consented to all scopes",
                        req.state());
            }
            return new AuthorizeResult.ConsentRequired(scopes, req.state());
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

    /**
     * Test whether {@code prompt} (an OIDC space-separated prompt list) contains
     * {@code value}. Null/blank prompt is treated as the empty list.
     */
    private static boolean promptContains(String prompt, String value) {
        if (prompt == null || prompt.isBlank()) return false;
        for (String token : prompt.trim().split("\\s+")) {
            if (token.equals(value)) return true;
        }
        return false;
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
