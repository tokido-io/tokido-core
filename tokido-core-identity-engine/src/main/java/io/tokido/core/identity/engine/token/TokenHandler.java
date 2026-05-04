package io.tokido.core.identity.engine.token;

import io.tokido.core.identity.engine.EventSink;
import io.tokido.core.identity.engine.TokenSigner;
import io.tokido.core.identity.engine.authorize.AuthorizationCodeData;
import io.tokido.core.identity.engine.authorize.Pkce;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import io.tokido.core.identity.protocol.TokenRequest;
import io.tokido.core.identity.protocol.TokenResult;
import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import io.tokido.core.identity.spi.ClientSecret;
import io.tokido.core.identity.spi.ClientStore;
import io.tokido.core.identity.spi.GrantType;
import io.tokido.core.identity.spi.PersistedGrant;
import io.tokido.core.identity.spi.RefreshTokenUsage;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.TokenStore;
import io.tokido.core.identity.spi.UserStore;
import org.apiguardian.api.API;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Drives the OAuth/OIDC {@code /token} endpoint.
 *
 * <p>RC1 supports the {@code authorization_code} grant only; other grant
 * types return {@code unsupported_grant_type}. Refresh tokens are issued so
 * RC2 can later redeem them, but the {@code refresh_token} grant itself is
 * not implemented.
 *
 * <p>The flow on success:
 * <ol>
 *   <li>Authenticate the client using {@code req.authMethod} +
 *       {@code req.clientSecret} against {@link Client#secrets()}.</li>
 *   <li>Look up the authorization-code grant by handle.</li>
 *   <li>Verify (a) it belongs to this client and is of type
 *       {@link GrantType#AUTHORIZATION_CODE}, (b) it has not been consumed,
 *       (c) PKCE per RFC 7636, (d) {@code redirect_uri} matches the
 *       authorize-time value.</li>
 *   <li>Mark the code consumed (one-time-use; ADR-0008 theft detection wipes
 *       all grants on reuse).</li>
 *   <li>Build access + ID tokens (JWS-signed via {@link TokenSigner}).</li>
 *   <li>Issue a 32-byte refresh-token handle and persist it as a
 *       {@link GrantType#REFRESH_TOKEN}.</li>
 * </ol>
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2.RC1")
public final class TokenHandler {

    /** Default ID token lifetime (5 minutes is conventional). */
    static final Duration ID_TOKEN_LIFETIME = Duration.ofMinutes(5);

    /** Refresh-token handle entropy: 32 bytes Base64url no padding → 43 chars. */
    private static final int REFRESH_TOKEN_BYTE_LENGTH = 32;

    private final URI issuer;
    private final ClientStore clientStore;
    private final TokenStore tokenStore;
    private final UserStore userStore;
    private final ResourceStore resourceStore;
    private final KeyStore keyStore;
    private final TokenSigner tokenSigner;
    private final Clock clock;
    private final EventSink eventSink;

    public TokenHandler(URI issuer,
                        ClientStore clientStore,
                        TokenStore tokenStore,
                        UserStore userStore,
                        ResourceStore resourceStore,
                        KeyStore keyStore,
                        TokenSigner tokenSigner,
                        Clock clock,
                        EventSink eventSink) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.clientStore = Objects.requireNonNull(clientStore, "clientStore");
        this.tokenStore = Objects.requireNonNull(tokenStore, "tokenStore");
        this.userStore = Objects.requireNonNull(userStore, "userStore");
        this.resourceStore = Objects.requireNonNull(resourceStore, "resourceStore");
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
        this.tokenSigner = Objects.requireNonNull(tokenSigner, "tokenSigner");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.eventSink = Objects.requireNonNull(eventSink, "eventSink");
    }

    /**
     * Run the token flow.
     *
     * @param req the incoming token request
     * @return one of the {@link TokenResult} variants — see the class javadoc
     *         for which gates produce which variant
     */
    public TokenResult handle(TokenRequest req) {
        Objects.requireNonNull(req, "req");

        // 1. Authenticate client.
        Client client = clientStore.findById(req.clientId());
        if (client == null) {
            return new TokenResult.Error("invalid_client", "unknown client: " + req.clientId());
        }
        if (!client.enabled()) {
            return new TokenResult.Error("invalid_client", "client is disabled");
        }
        if (!client.tokenEndpointAuthMethods().contains(req.authMethod())) {
            return new TokenResult.Error(
                    "invalid_client", "auth method not allowed for client: " + req.authMethod());
        }
        if (req.authMethod() != ClientAuthenticationMethod.NONE) {
            if (!authenticateSecret(client, req.clientSecret())) {
                return new TokenResult.Error("invalid_client", "client authentication failed");
            }
        }

        // 2. Dispatch on grant type.
        return switch (req.grantType()) {
            case "authorization_code" -> handleAuthorizationCode(req, client);
            case "refresh_token" -> handleRefreshToken(req, client);
            default -> new TokenResult.Error(
                    "unsupported_grant_type", "grant_type not supported: " + req.grantType());
        };
    }

    // ---- authorization_code grant ----

    private TokenResult handleAuthorizationCode(TokenRequest req, Client client) {
        // Per RFC 6749 §5.2 unauthorized_client: the authenticated client is
        // not authorized to use this authorization grant type. AuthorizeHandler
        // gates the same constraint at the front door, but a client could
        // present a code obtained when its grant-type allow-list was wider
        // (or could attempt with a stolen code) — so re-check at redemption.
        if (!client.allowedGrantTypes().contains(GrantType.AUTHORIZATION_CODE)) {
            return new TokenResult.Error(
                    "unauthorized_client",
                    "client not allowed to use authorization_code grant");
        }
        if (req.code() == null || req.code().isBlank()) {
            return new TokenResult.Error("invalid_grant", "code is required");
        }

        PersistedGrant grant = tokenStore.findByHandle(req.code());
        if (grant == null) {
            return new TokenResult.Error("invalid_grant", "unknown or expired code");
        }
        if (grant.type() != GrantType.AUTHORIZATION_CODE) {
            return new TokenResult.Error("invalid_grant", "handle is not an authorization code");
        }
        if (!grant.clientId().equals(client.clientId())) {
            return new TokenResult.Error("invalid_grant", "code was not issued to this client");
        }

        // 3. ADR-0008 theft detection: a second presentation of an already-
        // consumed code wipes every grant for (subject, client) and emits an
        // audit event. The description must not leak the subject id.
        if (grant.consumedTime() != null) {
            tokenStore.removeAll(grant.subjectId(), grant.clientId());
            eventSink.emit(
                    "authorization_code.reuse",
                    clock.instant(),
                    Map.of(
                            "subject", grant.subjectId(),
                            "client", grant.clientId()));
            return new TokenResult.Error(
                    "invalid_grant", "authorization code reuse detected");
        }

        // 4. Decode the captured authorize-time data.
        AuthorizationCodeData data;
        try {
            data = AuthorizationCodeData.fromJson(grant.data());
        } catch (IllegalArgumentException e) {
            return new TokenResult.Error("invalid_grant", "code payload is malformed");
        }

        // 5. PKCE check (RFC 7636).
        if (data.codeChallenge() != null) {
            if (req.codeVerifier() == null || req.codeVerifier().isBlank()) {
                return new TokenResult.Error("invalid_grant", "code_verifier is required");
            }
            if (!Pkce.verify(req.codeVerifier(), data.codeChallenge(), data.codeChallengeMethod())) {
                return new TokenResult.Error("invalid_grant", "code_verifier does not match");
            }
        }

        // 6. redirect_uri rebinding check (RFC 6749 §4.1.3).
        if (!data.redirectUri().equals(req.redirectUri())) {
            return new TokenResult.Error("invalid_grant", "redirect_uri does not match");
        }

        // 7. Mark code consumed (one-time use).
        Instant now = clock.instant();
        PersistedGrant consumed = new PersistedGrant(
                grant.handle(), grant.type(), grant.subjectId(), grant.clientId(),
                grant.scopes(), grant.creationTime(), grant.expiration(),
                now, grant.data());
        tokenStore.store(consumed);

        // 8. Build + sign tokens.
        SigningKey key = keyStore.activeSigningKey(SignatureAlgorithm.RS256);

        String accessTokenPayload = new AccessTokenBuilder(issuer, clock)
                .build(grant.subjectId(), client.clientId(), grant.scopes(), client.accessTokenLifetime());
        String accessToken = tokenSigner.sign(accessTokenPayload, key);

        String idTokenPayload = new IdTokenBuilder(issuer, resourceStore, userStore, clock, ID_TOKEN_LIFETIME)
                .build(grant.subjectId(), client.clientId(), grant.scopes(),
                        data.nonce(), data.authTime());
        String idToken = tokenSigner.sign(idTokenPayload, key);

        // 9. Mint refresh token. Persist as REFRESH_TOKEN grant. The data
        // payload carries nonce + auth_time so the redemption path can
        // re-issue ID tokens with the same values per OIDC Core §12.1.
        String refreshHandle = RandomHandle.generate(REFRESH_TOKEN_BYTE_LENGTH);
        String refreshDataJson = new RefreshTokenData(data.nonce(), data.authTime()).toJson();
        PersistedGrant refreshGrant = new PersistedGrant(
                refreshHandle,
                GrantType.REFRESH_TOKEN,
                grant.subjectId(),
                client.clientId(),
                grant.scopes(),
                now,
                now.plus(client.refreshTokenLifetime()),
                null,
                refreshDataJson);
        tokenStore.store(refreshGrant);

        return new TokenResult.Success(
                accessToken,
                "Bearer",
                client.accessTokenLifetime(),
                refreshHandle,
                idToken,
                grant.scopes());
    }

    // ---- refresh_token grant ----

    /**
     * Refresh-token redemption per RFC 6749 §6 + OIDC Core §12.
     *
     * <p>Mirrors the auth-code path's gates: client must be allowed to use
     * the refresh_token grant, the handle must be a known unconsumed
     * REFRESH_TOKEN grant for this client, and reuse of an already-consumed
     * refresh token triggers ADR-0008 theft detection (wipe all grants for
     * subject/client + emit {@code refresh_token.reuse}).
     *
     * <p>Scopes may be narrowed by the {@code scope} request param (RFC
     * 6749 §6) but never widened. Rotation behaviour follows
     * {@link Client#refreshTokenUsage()}: {@link RefreshTokenUsage#ONE_TIME}
     * marks the old grant consumed and issues a fresh handle;
     * {@link RefreshTokenUsage#REUSE} leaves the old grant alone and
     * returns a null {@code refresh_token} in the response (the client
     * keeps using its existing handle).
     */
    private TokenResult handleRefreshToken(TokenRequest req, Client client) {
        // 1. Client allowed to use the refresh_token grant?
        if (!client.allowedGrantTypes().contains(GrantType.REFRESH_TOKEN)) {
            return new TokenResult.Error(
                    "unauthorized_client",
                    "client not allowed to use refresh_token grant");
        }
        // 2. Required field.
        if (req.refreshToken() == null || req.refreshToken().isBlank()) {
            return new TokenResult.Error("invalid_request", "refresh_token is required");
        }
        // 3. Lookup + binding checks.
        PersistedGrant grant = tokenStore.findByHandle(req.refreshToken());
        if (grant == null) {
            return new TokenResult.Error("invalid_grant", "unknown or expired refresh_token");
        }
        if (grant.type() != GrantType.REFRESH_TOKEN) {
            return new TokenResult.Error("invalid_grant", "handle is not a refresh token");
        }
        if (!grant.clientId().equals(client.clientId())) {
            return new TokenResult.Error("invalid_grant", "refresh_token does not match client");
        }
        // 4. Theft detection (ADR-0008): reuse of consumed refresh = client compromised.
        if (grant.consumedTime() != null) {
            eventSink.emit(
                    "refresh_token.reuse",
                    clock.instant(),
                    Map.of("subject", grant.subjectId(), "client", client.clientId()));
            tokenStore.removeAll(grant.subjectId(), client.clientId());
            return new TokenResult.Error("invalid_grant", "refresh token reuse detected");
        }
        // 5. Scope narrowing (RFC 6749 §6).
        Set<String> grantedScopes = grant.scopes();
        if (!req.scopes().isEmpty()) {
            if (!grantedScopes.containsAll(req.scopes())) {
                return new TokenResult.Error(
                        "invalid_scope", "requested scopes exceed granted scopes");
            }
            grantedScopes = req.scopes();
        }
        // 6. Recover nonce + auth_time so the new ID token preserves them
        // per OIDC Core §12.1.
        RefreshTokenData rtd;
        try {
            rtd = RefreshTokenData.fromJson(grant.data());
        } catch (RuntimeException e) {
            return new TokenResult.Error("invalid_grant", "refresh_token data corrupt");
        }
        // 7. Build + sign new tokens.
        Instant now = clock.instant();
        SigningKey key = keyStore.activeSigningKey(SignatureAlgorithm.RS256);
        String accessTokenPayload = new AccessTokenBuilder(issuer, clock)
                .build(grant.subjectId(), client.clientId(), grantedScopes, client.accessTokenLifetime());
        String accessToken = tokenSigner.sign(accessTokenPayload, key);
        String idToken = null;
        if (grantedScopes.contains("openid")) {
            String idTokenPayload = new IdTokenBuilder(issuer, resourceStore, userStore, clock, ID_TOKEN_LIFETIME)
                    .build(grant.subjectId(), client.clientId(), grantedScopes, rtd.nonce(), rtd.authTime());
            idToken = tokenSigner.sign(idTokenPayload, key);
        }
        // 8. Rotate refresh handle per the client's refresh-token usage policy.
        String newRefreshHandle = null;
        if (client.refreshTokenUsage() == RefreshTokenUsage.ONE_TIME) {
            // Mark the consumed handle so the next presentation triggers
            // theft detection.
            tokenStore.store(new PersistedGrant(
                    grant.handle(), grant.type(),
                    grant.subjectId(), grant.clientId(),
                    grant.scopes(), grant.creationTime(), grant.expiration(),
                    now, grant.data()));
            // Issue a fresh handle; carry the same RefreshTokenData payload
            // so subsequent ID-token issuances keep preserving the original
            // nonce + auth_time.
            newRefreshHandle = RandomHandle.generate(REFRESH_TOKEN_BYTE_LENGTH);
            tokenStore.store(new PersistedGrant(
                    newRefreshHandle, GrantType.REFRESH_TOKEN,
                    grant.subjectId(), client.clientId(),
                    grantedScopes, now,
                    now.plus(client.refreshTokenLifetime()),
                    null, grant.data()));
        }
        // For REUSE: leave the existing grant alone and return a null
        // refresh_token in the response (client keeps its existing handle).
        return new TokenResult.Success(
                accessToken, "Bearer", client.accessTokenLifetime(),
                newRefreshHandle, idToken, grantedScopes);
    }

    // ---- helpers ----

    /**
     * Constant-time secret comparison against every non-expired secret on the
     * client.
     *
     * @return true if {@code submitted} is non-null and equals (in
     *         constant time) at least one non-expired registered secret
     */
    private boolean authenticateSecret(Client client, String submitted) {
        if (submitted == null) return false;
        Instant now = clock.instant();
        byte[] submittedBytes = submitted.getBytes(StandardCharsets.UTF_8);
        boolean matched = false;
        // Iterate every secret to keep timing roughly uniform — early-return
        // would leak the position of the matching secret.
        for (ClientSecret secret : client.secrets()) {
            if (secret.expiration() != null && secret.expiration().isBefore(now)) {
                continue;
            }
            byte[] storedBytes = secret.value().getBytes(StandardCharsets.UTF_8);
            if (MessageDigest.isEqual(submittedBytes, storedBytes)) {
                matched = true;
            }
        }
        return matched;
    }
}
