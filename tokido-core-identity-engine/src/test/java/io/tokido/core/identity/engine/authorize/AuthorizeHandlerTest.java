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

/**
 * Tests for {@link AuthorizeHandler} covering the happy path plus every
 * non-{@code MfaRequired} {@link AuthorizeResult} variant. Stubs are inline
 * anonymous classes — no Map* fixtures — matching the engine module's
 * existing test style and keeping us off the identity-jwt → engine reactor
 * cycle.
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

        AuthorizeResult result = handler.handle(req, sampleSession());

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

        AuthorizeResult.Redirect redirect = (AuthorizeResult.Redirect) handler.handle(req, sampleSession());

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
                sampleRequest(client, "s"), sampleSession());

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

        AuthorizeResult.Redirect r = (AuthorizeResult.Redirect) handler.handle(req, sampleSession());
        // Expect "?foo=bar&code=..." (i.e., one '?' total).
        long questionMarks = r.redirectUri().toString().chars().filter(ch -> ch == '?').count();
        assertThat(questionMarks).isEqualTo(1);
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
                sampleRequest(client, "s"), sampleSession());
        AuthorizeResult.Redirect r2 = (AuthorizeResult.Redirect) handler.handle(
                sampleRequest(client, "s"), sampleSession());

        assertThat(r1.params().get("code")).isNotEqualTo(r2.params().get("code"));
        assertThat(tokens.stored).hasSize(2);
    }

    // ---- Error / LoginRequired / ConsentRequired branches ----

    @Test
    void unknownClient_returnsInvalidClientError() {
        Client client = sampleClient(true);
        ClientStore unknown = new ClientStore() {
            @Override public Client findById(String id) { return null; }
            @Override public boolean exists(String id) { return false; }
        };
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, unknown,
                consentStub(consentForAllScopes(client)),
                noopResourceStore(), new RecordingTokenStore());

        AuthorizeResult result = handler.handle(sampleRequest(client, "xyz"), sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.Error.class);
        AuthorizeResult.Error err = (AuthorizeResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_client");
        assertThat(err.description()).contains(client.clientId());
        assertThat(err.state()).isEqualTo("xyz");
    }

    @Test
    void disabledClient_returnsInvalidClientError() {
        Client enabled = sampleClient(true);
        Client disabled = new Client(
                enabled.clientId(), enabled.secrets(), enabled.redirectUris(),
                enabled.postLogoutRedirectUris(), enabled.allowedScopes(), enabled.allowedGrantTypes(),
                enabled.tokenEndpointAuthMethods(), enabled.requirePkce(), enabled.allowOfflineAccess(),
                enabled.accessTokenLifetime(), enabled.refreshTokenLifetime(), enabled.refreshTokenUsage(),
                enabled.claims(), /* enabled */ false);
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(disabled),
                consentStub(consentForAllScopes(disabled)),
                noopResourceStore(), new RecordingTokenStore());

        AuthorizeResult result = handler.handle(sampleRequest(disabled, "xyz"), sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.Error.class);
        AuthorizeResult.Error err = (AuthorizeResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_client");
        assertThat(err.description()).isNotBlank();
        assertThat(err.state()).isEqualTo("xyz");
    }

    @Test
    void mismatchedRedirectUri_returnsInvalidRequestErrorWithoutEchoingState() {
        // RFC 6749 §4.1.2.1: redirect_uri mismatch MUST NOT redirect AND MUST
        // NOT echo state. The Error returned for this branch must carry
        // state == null so the adapter renders a 400 page rather than redirecting.
        Client client = sampleClient(true);
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(), new RecordingTokenStore());

        AuthorizeRequest badRedirect = new AuthorizeRequest(
                client.clientId(), "code", "https://evil.example/cb",
                Set.of("openid"), "xyz-state", null,
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());

        AuthorizeResult result = handler.handle(badRedirect, sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.Error.class);
        AuthorizeResult.Error err = (AuthorizeResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_request");
        assertThat(err.description()).containsIgnoringCase("redirect_uri");
        // Critical: state is NOT echoed.
        assertThat(err.state()).isNull();
    }

    @Test
    void unsupportedResponseType_returnsErrorWithEchoedState() {
        Client client = sampleClient(true);
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(), new RecordingTokenStore());

        AuthorizeRequest badResponseType = new AuthorizeRequest(
                client.clientId(), "token", "https://app.example/cb",
                Set.of("openid"), "xyz-state", null,
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());

        AuthorizeResult result = handler.handle(badResponseType, sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.Error.class);
        AuthorizeResult.Error err = (AuthorizeResult.Error) result;
        assertThat(err.code()).isEqualTo("unsupported_response_type");
        assertThat(err.state()).isEqualTo("xyz-state");
    }

    @Test
    void disallowedScope_returnsInvalidScopeErrorWithOffendingScopeName() {
        Client client = sampleClient(true);
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(), new RecordingTokenStore());

        AuthorizeRequest badScope = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb",
                Set.of("openid", "admin"), "xyz-state", null,
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());

        AuthorizeResult result = handler.handle(badScope, sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.Error.class);
        AuthorizeResult.Error err = (AuthorizeResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_scope");
        assertThat(err.description()).contains("admin");
        assertThat(err.state()).isEqualTo("xyz-state");
    }

    @Test
    void missingPkce_whenClientRequiresPkce_returnsInvalidRequestError() {
        Client client = sampleClient(true); // requirePkce = true
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(), new RecordingTokenStore());

        AuthorizeRequest noPkce = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb",
                Set.of("openid"), "xyz-state", null,
                /* codeChallenge */ null, null,
                null, Set.of(), null, null, null, null, Map.of());

        AuthorizeResult result = handler.handle(noPkce, sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.Error.class);
        AuthorizeResult.Error err = (AuthorizeResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_request");
        assertThat(err.description()).containsIgnoringCase("code_challenge");
        assertThat(err.state()).isEqualTo("xyz-state");
    }

    @Test
    void pkceNotRequired_andMissing_proceedsToHappyPath() {
        // Negative of branch 5: when client.requirePkce is false, missing
        // code_challenge must NOT produce an error.
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

        AuthorizeResult result = handler.handle(req, sampleSession());
        assertThat(result).isInstanceOf(AuthorizeResult.Redirect.class);
    }

    @Test
    void anonymousSession_returnsLoginRequired() {
        Client client = sampleClient(true);
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(consentForAllScopes(client)),
                noopResourceStore(), new RecordingTokenStore());

        AuthorizeResult result = handler.handle(sampleRequest(client, "s"), AuthenticationState.anonymous());

        assertThat(result).isInstanceOf(AuthorizeResult.LoginRequired.class);
        AuthorizeResult.LoginRequired lr = (AuthorizeResult.LoginRequired) result;
        assertThat(lr.reason()).isNull();
    }

    @Test
    void noPriorConsent_returnsConsentRequired() {
        Client client = sampleClient(true);
        ConsentStore noConsent = new ConsentStore() {
            @Override public Consent find(String s, String c) { return null; }
            @Override public void store(Consent c) { throw new UnsupportedOperationException(); }
            @Override public void remove(String s, String c) { throw new UnsupportedOperationException(); }
        };
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                noConsent, noopResourceStore(), new RecordingTokenStore());

        AuthorizeResult result = handler.handle(sampleRequest(client, "xyz-state"), sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.ConsentRequired.class);
        AuthorizeResult.ConsentRequired cr = (AuthorizeResult.ConsentRequired) result;
        assertThat(cr.requestedScopes()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(cr.state()).isEqualTo("xyz-state");
    }

    @Test
    void partialConsent_returnsConsentRequired() {
        Client client = sampleClient(true);
        Consent partial = new Consent("user-123", client.clientId(),
                Set.of("openid"), Instant.parse("2027-01-01T00:00:00Z"));
        AuthorizeHandler handler = new AuthorizeHandler(
                ISSUER, FIXED_CLOCK, clientStub(client),
                consentStub(partial), noopResourceStore(), new RecordingTokenStore());

        AuthorizeResult result = handler.handle(sampleRequest(client, "xyz-state"), sampleSession());

        assertThat(result).isInstanceOf(AuthorizeResult.ConsentRequired.class);
        AuthorizeResult.ConsentRequired cr = (AuthorizeResult.ConsentRequired) result;
        assertThat(cr.requestedScopes()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(cr.state()).isEqualTo("xyz-state");
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
    private static AuthenticationState sampleSession() {
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
        // Task 17 happy path does not consult the resource store; every method UoEs
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
