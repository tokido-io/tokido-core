package io.tokido.core.identity.engine.token;

import io.tokido.core.identity.engine.EventSink;
import io.tokido.core.identity.engine.TokenSigner;
import io.tokido.core.identity.engine.authorize.AuthorizationCodeData;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import io.tokido.core.identity.protocol.TokenRequest;
import io.tokido.core.identity.protocol.TokenResult;
import io.tokido.core.identity.spi.AuthenticationResult;
import io.tokido.core.identity.spi.BrokeredAuthentication;
import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import io.tokido.core.identity.spi.ClientSecret;
import io.tokido.core.identity.spi.ClientStore;
import io.tokido.core.identity.spi.GrantType;
import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.PersistedGrant;
import io.tokido.core.identity.spi.ProtectedResource;
import io.tokido.core.identity.spi.RefreshTokenUsage;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.TokenStore;
import io.tokido.core.identity.spi.User;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.identity.spi.UserStore;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Per-branch tests for {@link TokenHandler} covering the
 * authorization_code happy path, ADR-0008 theft detection, every
 * {@code invalid_client} / {@code invalid_grant} /
 * {@code unsupported_grant_type} branch, and the refresh-token issuance.
 *
 * <p>Stubs are inline anonymous classes — no Map* fixtures — to stay clear
 * of the identity-jwt → engine reactor cycle and to keep the engine
 * module's existing test style.
 */
class TokenHandlerTest {

    private static final URI ISSUER = URI.create("https://issuer.example/");
    private static final Instant NOW = Instant.parse("2026-05-02T12:00:00Z");
    private static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);

    private static final String CODE = "AUTHCODE_HANDLE";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String REDIRECT = "https://app.example/cb";

    // ---- happy path ----

    @Test
    void happyPathReturnsSuccessWithAccessIdAndRefreshTokens() {
        Client client = publicClient();
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(authCodeGrant(client, null));

        TokenHandler handler = handler(client, tokens, recordingSigner());

        TokenResult result = handler.handle(authCodeRequest(client, ClientAuthenticationMethod.NONE, null));

        assertThat(result).isInstanceOf(TokenResult.Success.class);
        TokenResult.Success ok = (TokenResult.Success) result;
        assertThat(ok.tokenType()).isEqualTo("Bearer");
        assertThat(ok.expiresIn()).isEqualTo(client.accessTokenLifetime());
        assertThat(ok.accessToken()).isNotNull().startsWith("signed.");
        assertThat(ok.idToken()).isNotNull().startsWith("signed.");
        assertThat(ok.refreshToken()).isNotBlank();
        assertThat(ok.scope()).containsExactlyInAnyOrder("openid", "profile");

        // Code grant re-stored with consumedTime set.
        PersistedGrant consumed = tokens.lookup(CODE);
        assertThat(consumed.consumedTime()).isEqualTo(NOW);

        // Refresh-token grant persisted as REFRESH_TOKEN.
        List<PersistedGrant> refreshGrants = tokens.byType(GrantType.REFRESH_TOKEN);
        assertThat(refreshGrants).hasSize(1);
        PersistedGrant refresh = refreshGrants.get(0);
        assertThat(refresh.handle()).isEqualTo(ok.refreshToken());
        assertThat(refresh.subjectId()).isEqualTo("user-1");
        assertThat(refresh.clientId()).isEqualTo(client.clientId());
        assertThat(refresh.scopes()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(refresh.creationTime()).isEqualTo(NOW);
        assertThat(refresh.expiration()).isEqualTo(NOW.plus(client.refreshTokenLifetime()));
        assertThat(refresh.consumedTime()).isNull();
        // Refresh data payload carries nonce + authTime for OIDC Core §12.1
        // claim preservation across refreshes.
        RefreshTokenData rtd = RefreshTokenData.fromJson(refresh.data());
        assertThat(rtd.nonce()).isEqualTo("n-0");
        assertThat(rtd.authTime()).isEqualTo(Instant.parse("2026-05-02T11:55:00Z"));
    }

    @Test
    void happyPathSignsBothTokensWithActiveKey() {
        Client client = publicClient();
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(authCodeGrant(client, null));
        RecordingSigner signer = recordingSigner();
        TokenHandler handler = handler(client, tokens, signer);

        handler.handle(authCodeRequest(client, ClientAuthenticationMethod.NONE, null));

        // Both signatures used the same active key.
        assertThat(signer.calls).hasSize(2);
        assertThat(signer.calls.get(0).key().kid()).isEqualTo("test-kid");
        assertThat(signer.calls.get(1).key().kid()).isEqualTo("test-kid");
    }

    // ---- invalid_client ----

    @Test
    void unknownClient_returnsInvalidClient() {
        TokenHandler handler = new TokenHandler(
                ISSUER,
                emptyClientStore(),
                new RecordingTokenStore(),
                noClaimsUserStore(),
                emptyResourceStore(),
                staticKeyStore(),
                recordingSigner(),
                FIXED,
                EventSink.noop());

        TokenResult result = handler.handle(authCodeRequest(publicClient(), ClientAuthenticationMethod.NONE, null));

        TokenResult.Error err = (TokenResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_client");
    }

    @Test
    void disabledClient_returnsInvalidClient() {
        Client enabled = publicClient();
        Client disabled = new Client(
                enabled.clientId(), enabled.secrets(), enabled.redirectUris(),
                enabled.postLogoutRedirectUris(), enabled.allowedScopes(), enabled.allowedGrantTypes(),
                enabled.tokenEndpointAuthMethods(), enabled.requirePkce(), enabled.allowOfflineAccess(),
                enabled.accessTokenLifetime(), enabled.refreshTokenLifetime(), enabled.refreshTokenUsage(),
                enabled.claims(), /* enabled */ false);
        TokenHandler handler = handler(disabled, new RecordingTokenStore(), recordingSigner());

        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(disabled, ClientAuthenticationMethod.NONE, null));

        assertThat(err.code()).isEqualTo("invalid_client");
    }

    @Test
    void wrongClientSecret_returnsInvalidClient() {
        Client confidential = confidentialClient();
        TokenHandler handler = handler(confidential, new RecordingTokenStore(), recordingSigner());

        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(confidential, ClientAuthenticationMethod.CLIENT_SECRET_POST, "wrong-secret"));

        assertThat(err.code()).isEqualTo("invalid_client");
    }

    @Test
    void authMethodNotInClientAllowedSet_returnsInvalidClient() {
        // Client only allows CLIENT_SECRET_BASIC; request submits CLIENT_SECRET_POST.
        Client confidential = confidentialClient();
        Client basicOnly = new Client(
                confidential.clientId(), confidential.secrets(), confidential.redirectUris(),
                confidential.postLogoutRedirectUris(), confidential.allowedScopes(),
                confidential.allowedGrantTypes(),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                confidential.requirePkce(), confidential.allowOfflineAccess(),
                confidential.accessTokenLifetime(), confidential.refreshTokenLifetime(),
                confidential.refreshTokenUsage(), confidential.claims(), confidential.enabled());
        TokenHandler handler = handler(basicOnly, new RecordingTokenStore(), recordingSigner());

        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(basicOnly, ClientAuthenticationMethod.CLIENT_SECRET_POST, "shh"));

        assertThat(err.code()).isEqualTo("invalid_client");
    }

    @Test
    void publicClient_whenNoneNotAllowed_returnsInvalidClient() {
        Client publicNoNone = new Client(
                "client-1", Set.of(),
                Set.of(REDIRECT), Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), // NONE not present
                /* requirePkce */ true, false,
                Duration.ofMinutes(15), Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME, Map.of(), true);
        TokenHandler handler = handler(publicNoNone, new RecordingTokenStore(), recordingSigner());

        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(publicNoNone, ClientAuthenticationMethod.NONE, null));

        assertThat(err.code()).isEqualTo("invalid_client");
    }

    @Test
    void confidentialClientHappyPath_passesSecretCheck() {
        Client confidential = confidentialClient();
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(authCodeGrant(confidential, null));
        TokenHandler handler = handler(confidential, tokens, recordingSigner());

        TokenResult result = handler.handle(
                authCodeRequest(confidential, ClientAuthenticationMethod.CLIENT_SECRET_POST, "shh"));

        assertThat(result).isInstanceOf(TokenResult.Success.class);
    }

    @Test
    void expiredSecretDoesNotAuthenticate() {
        // Single secret on the client is expired; no other secrets — must fail.
        Client expiredOnly = new Client(
                "client-1",
                Set.of(new ClientSecret("shh", null, NOW.minusSeconds(60))),
                Set.of(REDIRECT), Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST),
                true, false,
                Duration.ofMinutes(15), Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME, Map.of(), true);
        TokenHandler handler = handler(expiredOnly, new RecordingTokenStore(), recordingSigner());

        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(expiredOnly, ClientAuthenticationMethod.CLIENT_SECRET_POST, "shh"));

        assertThat(err.code()).isEqualTo("invalid_client");
    }

    // ---- unsupported_grant_type ----

    @Test
    void refreshTokenGrant_returnsUnsupportedGrantType() {
        Client client = publicClient();
        TokenHandler handler = handler(client, new RecordingTokenStore(), recordingSigner());

        TokenRequest req = new TokenRequest(
                "refresh_token", client.clientId(), null,
                ClientAuthenticationMethod.NONE,
                null, null, null, "any-refresh-handle", Set.of(), Map.of());
        TokenResult.Error err = (TokenResult.Error) handler.handle(req);

        assertThat(err.code()).isEqualTo("unsupported_grant_type");
    }

    @Test
    void clientNotAllowedToUseCodeGrant_returnsUnauthorizedClient() {
        // Per RFC 6749 §5.2: defense-in-depth check at the token endpoint.
        // AuthorizeHandler gates the same constraint earlier; redeeming a
        // code stolen / issued before the client's grant-type allow-list
        // changed must still be rejected.
        Client noCodeGrant = new Client(
                "client-1", Set.of(),
                Set.of(REDIRECT), Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.REFRESH_TOKEN), // no AUTHORIZATION_CODE
                Set.of(ClientAuthenticationMethod.NONE),
                true, false,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(), true);
        TokenHandler handler = handler(noCodeGrant, new RecordingTokenStore(), recordingSigner());
        TokenRequest req = authCodeRequest(noCodeGrant, ClientAuthenticationMethod.NONE, null);

        TokenResult.Error err = (TokenResult.Error) handler.handle(req);

        assertThat(err.code()).isEqualTo("unauthorized_client");
    }

    @Test
    void clientCredentialsGrant_returnsUnsupportedGrantType() {
        Client client = publicClient();
        TokenHandler handler = handler(client, new RecordingTokenStore(), recordingSigner());

        TokenRequest req = new TokenRequest(
                "client_credentials", client.clientId(), null,
                ClientAuthenticationMethod.NONE,
                null, null, null, null, Set.of(), Map.of());
        TokenResult.Error err = (TokenResult.Error) handler.handle(req);

        assertThat(err.code()).isEqualTo("unsupported_grant_type");
    }

    // ---- invalid_grant: code lookups ----

    @Test
    void unknownCode_returnsInvalidGrant() {
        Client client = publicClient();
        // tokens has nothing.
        TokenHandler handler = handler(client, new RecordingTokenStore(), recordingSigner());

        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(client, ClientAuthenticationMethod.NONE, null));

        assertThat(err.code()).isEqualTo("invalid_grant");
    }

    @Test
    void codeBelongsToDifferentClient_returnsInvalidGrant() {
        Client client = publicClient();
        // Grant is for "other-client", but the request submits client-1.
        AuthorizationCodeData data = sampleCodeData(null);
        Instant created = NOW.minusSeconds(10);
        PersistedGrant otherClientGrant = new PersistedGrant(
                CODE, GrantType.AUTHORIZATION_CODE, "user-1", "other-client",
                Set.of("openid", "profile"),
                created, created.plus(Duration.ofMinutes(10)), null, data.toJson());
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(otherClientGrant);

        TokenHandler handler = handler(client, tokens, recordingSigner());
        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(client, ClientAuthenticationMethod.NONE, null));

        assertThat(err.code()).isEqualTo("invalid_grant");
    }

    @Test
    void codeIsRefreshTokenType_returnsInvalidGrant() {
        // The handle exists but resolves to a REFRESH_TOKEN grant — the
        // authorization_code branch must reject it.
        Client client = publicClient();
        AuthorizationCodeData data = sampleCodeData(null);
        Instant created = NOW.minusSeconds(10);
        PersistedGrant refreshShaped = new PersistedGrant(
                CODE, GrantType.REFRESH_TOKEN, "user-1", client.clientId(),
                Set.of("openid"),
                created, created.plus(Duration.ofDays(30)), null, data.toJson());
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(refreshShaped);

        TokenHandler handler = handler(client, tokens, recordingSigner());
        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(client, ClientAuthenticationMethod.NONE, null));

        assertThat(err.code()).isEqualTo("invalid_grant");
    }

    // ---- ADR-0008 theft detection ----

    @Test
    void consumedCode_returnsInvalidGrant_andWipesAllGrantsForSubjectClient() {
        // CRITICAL: ADR-0008 — replaying a consumed code must call
        // tokenStore.removeAll(subject, client) and return invalid_grant.
        Client client = publicClient();
        AuthorizationCodeData data = sampleCodeData(null);
        Instant created = NOW.minusSeconds(60);
        PersistedGrant consumed = new PersistedGrant(
                CODE, GrantType.AUTHORIZATION_CODE, "user-1", client.clientId(),
                Set.of("openid", "profile"),
                created, created.plus(Duration.ofMinutes(10)),
                /* consumedTime */ NOW.minusSeconds(30),
                data.toJson());
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(consumed);

        List<EventRecord> events = new ArrayList<>();
        EventSink recordingSink = (type, ts, attrs) -> events.add(new EventRecord(type, ts, attrs));

        TokenHandler handler = new TokenHandler(
                ISSUER, clientStub(client), tokens,
                noClaimsUserStore(), emptyResourceStore(),
                staticKeyStore(), recordingSigner(),
                FIXED, recordingSink);
        TokenResult.Error err = (TokenResult.Error) handler.handle(
                authCodeRequest(client, ClientAuthenticationMethod.NONE, null));

        assertThat(err.code()).isEqualTo("invalid_grant");
        // CRITICAL ASSERTION: removeAll was called.
        assertThat(tokens.removeAllCalls)
                .containsExactly(new RemoveAllCall("user-1", client.clientId()));
        // Audit event is good hygiene; we also assert it because we emit it.
        assertThat(events).hasSize(1);
        assertThat(events.get(0).type()).isEqualTo("authorization_code.reuse");
    }

    // ---- invalid_grant: PKCE + redirect_uri ----

    @Test
    void wrongVerifier_returnsInvalidGrant() {
        Client client = publicClient();
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(authCodeGrant(client, null));
        TokenHandler handler = handler(client, tokens, recordingSigner());

        TokenRequest req = new TokenRequest(
                "authorization_code", client.clientId(), null,
                ClientAuthenticationMethod.NONE,
                CODE, REDIRECT,
                /* codeVerifier */ "wrong-verifier",
                null, Set.of(), Map.of());
        TokenResult.Error err = (TokenResult.Error) handler.handle(req);

        assertThat(err.code()).isEqualTo("invalid_grant");
    }

    @Test
    void missingVerifier_whenChallengePresent_returnsInvalidGrant() {
        Client client = publicClient();
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(authCodeGrant(client, null));
        TokenHandler handler = handler(client, tokens, recordingSigner());

        TokenRequest req = new TokenRequest(
                "authorization_code", client.clientId(), null,
                ClientAuthenticationMethod.NONE,
                CODE, REDIRECT,
                /* codeVerifier */ null,
                null, Set.of(), Map.of());
        TokenResult.Error err = (TokenResult.Error) handler.handle(req);

        assertThat(err.code()).isEqualTo("invalid_grant");
    }

    @Test
    void redirectUriMismatch_returnsInvalidGrant() {
        Client client = publicClient();
        RecordingTokenStore tokens = new RecordingTokenStore();
        tokens.putHandle(authCodeGrant(client, null));
        TokenHandler handler = handler(client, tokens, recordingSigner());

        TokenRequest req = new TokenRequest(
                "authorization_code", client.clientId(), null,
                ClientAuthenticationMethod.NONE,
                CODE,
                /* redirect_uri */ "https://app.example/wrong",
                VERIFIER, null, Set.of(), Map.of());
        TokenResult.Error err = (TokenResult.Error) handler.handle(req);

        assertThat(err.code()).isEqualTo("invalid_grant");
    }

    // ---- helpers ----

    private static Client publicClient() {
        return new Client(
                "client-1", Set.of(),
                Set.of(REDIRECT), Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.NONE),
                /* requirePkce */ true,
                /* allowOfflineAccess */ false,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                /* enabled */ true);
    }

    private static Client confidentialClient() {
        return new Client(
                "client-1",
                Set.of(new ClientSecret("shh", null, null)),
                Set.of(REDIRECT), Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST),
                true, false,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                true);
    }

    private static AuthorizationCodeData sampleCodeData(String authTimeOverride) {
        return new AuthorizationCodeData(
                "n-0",
                CHALLENGE,
                "S256",
                Set.of("openid", "profile"),
                REDIRECT,
                authTimeOverride == null ? Instant.parse("2026-05-02T11:55:00Z") : Instant.parse(authTimeOverride),
                null);
    }

    private static PersistedGrant authCodeGrant(Client client, Instant consumedTime) {
        AuthorizationCodeData data = sampleCodeData(null);
        Instant created = NOW.minusSeconds(10);
        return new PersistedGrant(
                CODE, GrantType.AUTHORIZATION_CODE, "user-1", client.clientId(),
                Set.of("openid", "profile"),
                created, created.plus(Duration.ofMinutes(10)),
                consumedTime,
                data.toJson());
    }

    private static TokenRequest authCodeRequest(Client client, ClientAuthenticationMethod method, String secret) {
        return new TokenRequest(
                "authorization_code",
                client.clientId(),
                secret,
                method,
                CODE,
                REDIRECT,
                VERIFIER,
                null,
                Set.of(),
                Map.of());
    }

    private static TokenHandler handler(Client client, TokenStore tokens, TokenSigner signer) {
        return new TokenHandler(
                ISSUER, clientStub(client), tokens,
                noClaimsUserStore(), emptyResourceStore(),
                staticKeyStore(), signer,
                FIXED, EventSink.noop());
    }

    private static ClientStore clientStub(Client client) {
        Map<String, Client> idx = new HashMap<>();
        idx.put(client.clientId(), client);
        return new ClientStore() {
            @Override public Client findById(String id) { return idx.get(id); }
            @Override public boolean exists(String id) { return idx.containsKey(id); }
        };
    }

    private static ClientStore emptyClientStore() {
        return new ClientStore() {
            @Override public Client findById(String id) { return null; }
            @Override public boolean exists(String id) { return false; }
        };
    }

    private static UserStore noClaimsUserStore() {
        return new UserStore() {
            @Override public User findById(String s) { throw new UnsupportedOperationException(); }
            @Override public User findByUsername(String u) { throw new UnsupportedOperationException(); }
            @Override public AuthenticationResult authenticate(String u, String c) { throw new UnsupportedOperationException(); }
            @Override public User findByExternalProvider(String p, String s) { throw new UnsupportedOperationException(); }
            @Override public User createFromExternalProvider(BrokeredAuthentication b) { throw new UnsupportedOperationException(); }
            @Override public Set<UserClaim> claims(String s) { return Set.of(); }
        };
    }

    private static ResourceStore emptyResourceStore() {
        return new ResourceStore() {
            // ID-token builder consults findIdentityScope; return null for everything.
            @Override public IdentityScope findIdentityScope(String n) { return null; }
            @Override public ProtectedResource findProtectedResource(String n) { throw new UnsupportedOperationException(); }
            @Override public Set<IdentityScope> findIdentityScopesByName(Set<String> ns) { throw new UnsupportedOperationException(); }
            @Override public Set<ProtectedResource> findResourcesByScope(Set<String> ns) { throw new UnsupportedOperationException(); }
        };
    }

    private static KeyStore staticKeyStore() {
        SigningKey key = new SigningKey(
                "test-kid",
                SignatureAlgorithm.RS256,
                new KeyMaterial(new byte[] {0x00}, SignatureAlgorithm.RS256),
                KeyState.ACTIVE,
                NOW.minusSeconds(3600),
                NOW.plusSeconds(3600));
        return new KeyStore() {
            @Override public SigningKey activeSigningKey(SignatureAlgorithm a) { return key; }
            @Override public Set<SigningKey> allKeys() { return Set.of(key); }
        };
    }

    private static RecordingSigner recordingSigner() { return new RecordingSigner(); }

    /** Records every call to {@link TokenSigner#sign}. */
    private static final class RecordingSigner implements TokenSigner {
        final List<SignCall> calls = new ArrayList<>();
        @Override public String sign(String payload, SigningKey key) {
            calls.add(new SignCall(payload, key));
            return "signed." + Integer.toHexString(payload.hashCode());
        }
    }

    private record SignCall(String payload, SigningKey key) {}
    private record EventRecord(String type, Instant timestamp, Map<String, Object> attributes) {}
    private record RemoveAllCall(String subjectId, String clientId) {}

    /** Captures every {@code store} write and {@code removeAll} call. */
    private static final class RecordingTokenStore implements TokenStore {
        private final Map<String, PersistedGrant> byHandle = new HashMap<>();
        final List<RemoveAllCall> removeAllCalls = new ArrayList<>();

        void putHandle(PersistedGrant grant) { byHandle.put(grant.handle(), grant); }
        PersistedGrant lookup(String handle) { return byHandle.get(handle); }

        List<PersistedGrant> byType(GrantType type) {
            return byHandle.values().stream().filter(g -> g.type() == type).toList();
        }

        @Override public void store(PersistedGrant grant) { byHandle.put(grant.handle(), grant); }
        @Override public PersistedGrant findByHandle(String handle) { return byHandle.get(handle); }
        @Override public void remove(String handle) { byHandle.remove(handle); }
        @Override public void removeAll(String subjectId, String clientId) {
            removeAllCalls.add(new RemoveAllCall(subjectId, clientId));
            byHandle.values().removeIf(g -> g.subjectId().equals(subjectId) && g.clientId().equals(clientId));
        }
        @Override public void removeAll(String subjectId, String clientId, GrantType type) {
            byHandle.values().removeIf(g -> g.subjectId().equals(subjectId)
                    && g.clientId().equals(clientId) && g.type() == type);
        }
    }
}
