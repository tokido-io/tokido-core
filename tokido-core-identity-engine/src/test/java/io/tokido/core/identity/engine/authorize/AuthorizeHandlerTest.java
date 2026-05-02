package io.tokido.core.identity.engine.authorize;

import io.tokido.core.identity.protocol.AuthenticationState;
import io.tokido.core.identity.protocol.AuthorizeRequest;
import io.tokido.core.identity.protocol.AuthorizeResult;
import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import io.tokido.core.identity.spi.ClientStore;
import io.tokido.core.identity.spi.Consent;
import io.tokido.core.identity.spi.ConsentStore;
import io.tokido.core.identity.spi.GrantType;
import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.PersistedGrant;
import io.tokido.core.identity.spi.ProtectedResource;
import io.tokido.core.identity.spi.RefreshTokenUsage;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.TokenStore;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Happy-path tests for {@link AuthorizeHandler}. Error/login/consent branches
 * land in Task 17. Stubs are inline anonymous classes — no Map* fixtures —
 * matching the engine module's existing test style and keeping us off the
 * identity-jwt → engine reactor cycle.
 */
class AuthorizeHandlerTest {

    private static final URI ISSUER = URI.create("https://issuer.example/");
    private static final Instant FIXED_NOW = Instant.parse("2026-05-02T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    @Test
    void happyPathReturnsRedirectWithCodeStateAndIss() {
        Client client = sampleClient(true);
        RecordingTokenStore tokens = new RecordingTokenStore();
        ConsentStore consents = consentStub(consentForAllScopes(client));

        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK,
                clientStub(client),
                consents,
                noopResourceStore(),
                tokens);

        AuthorizeRequest req = sampleRequest(client, "xyz-state");
        AuthorizationCodeData expectedAuthState = sampleAuthState();

        AuthorizeResult result = handler.handle(req, sampleSessionFor(client));

        // Variant.
        assertThat(result).isInstanceOf(AuthorizeResult.Redirect.class);
        AuthorizeResult.Redirect redirect = (AuthorizeResult.Redirect) result;

        // Params.
        assertThat(redirect.params()).containsKey("code");
        String code = redirect.params().get("code");
        assertThat(code).isNotBlank();
        assertThat(redirect.params().get("state")).isEqualTo("xyz-state");
        assertThat(redirect.params().get("iss")).isEqualTo(ISSUER.toString());

        // Redirect URI shape.
        assertThat(redirect.redirectUri().toString())
                .startsWith("https://app.example/cb?")
                .contains("code=" + code)
                .contains("state=xyz-state")
                .contains("iss=https%3A%2F%2Fissuer.example%2F");

        // Persisted grant.
        assertThat(tokens.stored).hasSize(1);
        PersistedGrant grant = tokens.stored.get(0);
        assertThat(grant.handle()).isEqualTo(code);
        assertThat(grant.type()).isEqualTo(GrantType.AUTHORIZATION_CODE);
        assertThat(grant.subjectId()).isEqualTo("user-123");
        assertThat(grant.clientId()).isEqualTo(client.clientId());
        assertThat(grant.scopes()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(grant.creationTime()).isEqualTo(FIXED_NOW);
        assertThat(grant.expiration()).isEqualTo(FIXED_NOW.plus(AuthorizeHandler.AUTHORIZATION_CODE_LIFETIME));
        assertThat(grant.consumedTime()).isNull();

        // The data payload deserializes back to what we put in.
        AuthorizationCodeData deserialized = AuthorizationCodeData.fromJson(grant.data());
        assertThat(deserialized.scopes()).containsExactlyInAnyOrderElementsOf(expectedAuthState.scopes());
        assertThat(deserialized.redirectUri()).isEqualTo(expectedAuthState.redirectUri());
        assertThat(deserialized.nonce()).isEqualTo(expectedAuthState.nonce());
        assertThat(deserialized.codeChallenge()).isEqualTo(expectedAuthState.codeChallenge());
        assertThat(deserialized.codeChallengeMethod()).isEqualTo(expectedAuthState.codeChallengeMethod());
        assertThat(deserialized.authTime()).isEqualTo(expectedAuthState.authTime());
        assertThat(deserialized.requestedAcr()).isEqualTo(expectedAuthState.requestedAcr());
    }

    @Test
    void redirectOmitsStateWhenRequestStateIsNull() {
        Client client = sampleClient(true);
        RecordingTokenStore tokens = new RecordingTokenStore();
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK,
                clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(),
                tokens);

        AuthorizeRequest req = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb",
                Set.of("openid"),
                /* state */ null,
                /* nonce */ "n-1",
                /* codeChallenge */ "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                /* codeChallengeMethod */ "S256",
                null, Set.of(), null, null, null, null, Map.of());

        AuthorizeResult.Redirect redirect = (AuthorizeResult.Redirect) handler.handle(req, sampleSessionFor(client));

        assertThat(redirect.params()).doesNotContainKey("state");
        assertThat(redirect.params()).containsKey("code");
        assertThat(redirect.params().get("iss")).isEqualTo(ISSUER.toString());
    }

    @Test
    void codeIs43CharBase64UrlNoPadding() {
        Client client = sampleClient(true);
        RecordingTokenStore tokens = new RecordingTokenStore();
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK,
                clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(),
                tokens);

        AuthorizeResult.Redirect redirect = (AuthorizeResult.Redirect) handler.handle(
                sampleRequest(client, "s"), sampleSessionFor(client));

        String code = redirect.params().get("code");
        // 32 bytes Base64url no-padding => 43 chars from {A-Z,a-z,0-9,-,_}.
        assertThat(code).hasSize(43).matches("[A-Za-z0-9_-]{43}");
    }

    @Test
    void redirectUriBaseAlreadyHasQueryStringStillAppendsParamsCorrectly() {
        // If the registered redirect URI already carries a query (rare but legal),
        // the handler must use '&' for the first appended param, not '?'.
        Client client = new Client(
                "client-1", Set.of(),
                Set.of("https://app.example/cb?foo=bar"),
                Set.of(), Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.NONE),
                true, false,
                Duration.ofMinutes(15), Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME, Map.of(), true);
        Consent consent = new Consent("user-123", client.clientId(),
                Set.of("openid"), Instant.parse("2027-01-01T00:00:00Z"));
        RecordingTokenStore tokens = new RecordingTokenStore();
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK,
                clientStub(client),
                consentStub(consent),
                noopResourceStore(),
                tokens);

        AuthorizeRequest req = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb?foo=bar",
                Set.of("openid"), "s", "n",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());

        AuthorizeResult.Redirect r = (AuthorizeResult.Redirect) handler.handle(req, sampleSessionFor(client));
        // Expect "?foo=bar&code=..." (i.e., one '?' total).
        long questionMarks = r.redirectUri().toString().chars().filter(ch -> ch == '?').count();
        assertThat(questionMarks).isEqualTo(1);
    }

    @Test
    void deferredBranchesThrowIllegalStateForTask17() {
        // Task 16 implements only the happy path; the validation gates each
        // throw IllegalStateException so Task 17 has a single, easily-spotted
        // place to swap in proper Error/LoginRequired/ConsentRequired variants.
        Client client = sampleClient(true);
        ClientStore unknownClient = new ClientStore() {
            @Override public Client findById(String id) { return null; }
            @Override public boolean exists(String id) { return false; }
        };
        AuthorizeHandler h1 = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, unknownClient,
                consentStub(consentForAllScopes(client)), noopResourceStore(), new RecordingTokenStore());
        assertThatThrownBy(() -> h1.handle(sampleRequest(client, "s"), sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("invalid_client");

        Client disabled = new Client(client.clientId(), client.secrets(), client.redirectUris(),
                client.postLogoutRedirectUris(), client.allowedScopes(), client.allowedGrantTypes(),
                client.tokenEndpointAuthMethods(), client.requirePkce(), client.allowOfflineAccess(),
                client.accessTokenLifetime(), client.refreshTokenLifetime(), client.refreshTokenUsage(),
                client.claims(), /* enabled */ false);
        AuthorizeHandler h2 = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(disabled),
                consentStub(consentForAllScopes(client)), noopResourceStore(), new RecordingTokenStore());
        assertThatThrownBy(() -> h2.handle(sampleRequest(disabled, "s"), sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("invalid_client");

        // Bad redirect URI.
        AuthorizeRequest badRedirect = new AuthorizeRequest(
                client.clientId(), "code", "https://evil.example/cb",
                Set.of("openid"), "s", null,
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());
        AuthorizeHandler h3 = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(consentForAllScopes(client)), noopResourceStore(), new RecordingTokenStore());
        assertThatThrownBy(() -> h3.handle(badRedirect, sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("redirect_uri");

        // Disallowed scope.
        AuthorizeRequest badScope = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb",
                Set.of("openid", "admin"), "s", null,
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());
        assertThatThrownBy(() -> h3.handle(badScope, sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("invalid_scope");

        // Wrong response_type.
        AuthorizeRequest badResponseType = new AuthorizeRequest(
                client.clientId(), "token", "https://app.example/cb",
                Set.of("openid"), "s", null,
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());
        assertThatThrownBy(() -> h3.handle(badResponseType, sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unsupported_response_type");

        // PKCE required but missing.
        AuthorizeRequest noPkce = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb",
                Set.of("openid"), "s", null,
                /* codeChallenge */ null, null,
                null, Set.of(), null, null, null, null, Map.of());
        assertThatThrownBy(() -> h3.handle(noPkce, sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("PKCE");

        // Anonymous session → login_required deferred branch.
        assertThatThrownBy(() -> h3.handle(sampleRequest(client, "s"), AuthenticationState.anonymous()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("login_required");

        // Authenticated but no consent.
        ConsentStore noConsent = new ConsentStore() {
            @Override public Consent find(String s, String c) { return null; }
            @Override public void store(Consent c) { throw new UnsupportedOperationException(); }
            @Override public void remove(String s, String c) { throw new UnsupportedOperationException(); }
        };
        AuthorizeHandler h4 = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                noConsent, noopResourceStore(), new RecordingTokenStore());
        assertThatThrownBy(() -> h4.handle(sampleRequest(client, "s"), sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("consent_required");

        // Consent present but does not cover requested scopes.
        Consent partial = new Consent("user-123", client.clientId(),
                Set.of("openid"), Instant.parse("2027-01-01T00:00:00Z"));
        AuthorizeHandler h5 = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(partial), noopResourceStore(), new RecordingTokenStore());
        assertThatThrownBy(() -> h5.handle(sampleRequest(client, "s"), sampleSessionFor(client)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("consent_required");
    }

    @Test
    void clientWithoutPkceRequirementSkipsPkceGate() {
        // PKCE-not-required client + no code_challenge → still happy-path.
        Client client = new Client(
                "client-1", Set.of(),
                Set.of("https://app.example/cb"),
                Set.of(), Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.NONE),
                /* requirePkce */ false, false,
                Duration.ofMinutes(15), Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME, Map.of(), true);
        Consent consent = new Consent("user-123", client.clientId(),
                Set.of("openid"), Instant.parse("2027-01-01T00:00:00Z"));
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK,
                clientStub(client),
                consentStub(consent),
                noopResourceStore(),
                new RecordingTokenStore());

        AuthorizeRequest req = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb",
                Set.of("openid"), "s", null,
                /* codeChallenge */ null, null,
                null, Set.of(), null, null, null, null, Map.of());

        AuthorizeResult result = handler.handle(req, sampleSessionFor(client));
        assertThat(result).isInstanceOf(AuthorizeResult.Redirect.class);
    }

    @Test
    void codeIsUniquePerInvocation() {
        Client client = sampleClient(true);
        RecordingTokenStore tokens = new RecordingTokenStore();
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK,
                clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(),
                tokens);

        AuthorizeResult.Redirect r1 = (AuthorizeResult.Redirect) handler.handle(
                sampleRequest(client, "s"), sampleSessionFor(client));
        AuthorizeResult.Redirect r2 = (AuthorizeResult.Redirect) handler.handle(
                sampleRequest(client, "s"), sampleSessionFor(client));

        assertThat(r1.params().get("code")).isNotEqualTo(r2.params().get("code"));
        assertThat(tokens.stored).hasSize(2);
    }

    // ---- helpers ----

    private static Client sampleClient(boolean enabled) {
        return new Client(
                "client-1",
                Set.of(),
                Set.of("https://app.example/cb"),
                Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.NONE),
                /* requirePkce */ true,
                /* allowOfflineAccess */ false,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                enabled);
    }

    private static AuthorizeRequest sampleRequest(Client client, String state) {
        return new AuthorizeRequest(
                client.clientId(),
                "code",
                "https://app.example/cb",
                Set.of("openid", "profile"),
                state,
                "n-0S6_WzA2Mj",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "S256",
                null,
                Set.of(),
                null, null, null, null, Map.of());
    }

    /** AuthenticationState that establishes a logged-in user. */
    private static AuthenticationState sampleSessionFor(Client client) {
        return new AuthenticationState(
                "user-123",
                Instant.parse("2026-05-02T11:55:00Z"),
                Set.of("pwd"),
                "urn:mace:incommon:iap:silver",
                Map.of());
    }

    /** Mirrors what we expect the handler to bake into the persisted code data. */
    private static AuthorizationCodeData sampleAuthState() {
        return new AuthorizationCodeData(
                "n-0S6_WzA2Mj",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "S256",
                Set.of("openid", "profile"),
                "https://app.example/cb",
                Instant.parse("2026-05-02T11:55:00Z"),
                "urn:mace:incommon:iap:silver");
    }

    private static Consent consentForAllScopes(Client client) {
        return new Consent("user-123", client.clientId(),
                Set.of("openid", "profile"),
                Instant.parse("2027-01-01T00:00:00Z"));
    }

    private static ClientStore clientStub(Client client) {
        Map<String, Client> idx = new HashMap<>();
        idx.put(client.clientId(), client);
        return new ClientStore() {
            @Override public Client findById(String id) { return idx.get(id); }
            @Override public boolean exists(String id) { return idx.containsKey(id); }
        };
    }

    private static ConsentStore consentStub(Consent consent) {
        return new ConsentStore() {
            @Override
            public Consent find(String s, String c) {
                if (consent.subjectId().equals(s) && consent.clientId().equals(c)) return consent;
                return null;
            }
            @Override public void store(Consent c) { throw new UnsupportedOperationException(); }
            @Override public void remove(String s, String c) { throw new UnsupportedOperationException(); }
        };
    }

    private static ResourceStore noopResourceStore() {
        // Task 16 happy path does not consult the resource store; every method UoEs
        // so we will catch any accidental call in a future task.
        return new ResourceStore() {
            @Override public IdentityScope findIdentityScope(String n) { throw new UnsupportedOperationException(); }
            @Override public ProtectedResource findProtectedResource(String n) { throw new UnsupportedOperationException(); }
            @Override public Set<IdentityScope> findIdentityScopesByName(Set<String> ns) { throw new UnsupportedOperationException(); }
            @Override public Set<ProtectedResource> findResourcesByScope(Set<String> ns) { throw new UnsupportedOperationException(); }
        };
    }

    /** Captures every {@link PersistedGrant} written by the handler. */
    private static final class RecordingTokenStore implements TokenStore {
        final List<PersistedGrant> stored = new ArrayList<>();

        @Override public void store(PersistedGrant grant) { stored.add(grant); }
        @Override public PersistedGrant findByHandle(String h) { throw new UnsupportedOperationException(); }
        @Override public void remove(String h) { throw new UnsupportedOperationException(); }
        @Override public void removeAll(String s, String c) { throw new UnsupportedOperationException(); }
        @Override public void removeAll(String s, String c, GrantType t) { throw new UnsupportedOperationException(); }
    }
}
