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
            default -> new TokenResult.Error(
                    "unsupported_grant_type", "grant_type not supported: " + req.grantType());
        };
    }

    // ---- authorization_code grant ----

    private TokenResult handleAuthorizationCode(TokenRequest req, Client client) {
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
                .build(grant.subjectId(), client.clientId(), grant.scopes(), data);
        String idToken = tokenSigner.sign(idTokenPayload, key);

        // 9. Mint refresh token. Persist as REFRESH_TOKEN grant for RC2.
        String refreshHandle = RandomHandle.generate(REFRESH_TOKEN_BYTE_LENGTH);
        PersistedGrant refreshGrant = new PersistedGrant(
                refreshHandle,
                GrantType.REFRESH_TOKEN,
                grant.subjectId(),
                client.clientId(),
                grant.scopes(),
                now,
                now.plus(client.refreshTokenLifetime()),
                null,
                "");
        tokenStore.store(refreshGrant);

        return new TokenResult.Success(
                accessToken,
                "Bearer",
                client.accessTokenLifetime(),
                refreshHandle,
                idToken,
                grant.scopes());
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
