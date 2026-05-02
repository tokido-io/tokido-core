package io.tokido.core.identity.engine;

import io.tokido.core.identity.engine.authorize.AuthorizationCodeData;
import io.tokido.core.identity.protocol.AuthenticationState;
import io.tokido.core.identity.protocol.AuthorizeRequest;
import io.tokido.core.identity.protocol.AuthorizeResult;
import io.tokido.core.identity.protocol.EndSessionRequest;
import io.tokido.core.identity.protocol.IntrospectionRequest;
import io.tokido.core.identity.protocol.RevocationRequest;
import io.tokido.core.identity.protocol.TokenRequest;
import io.tokido.core.identity.protocol.TokenResult;
import io.tokido.core.identity.protocol.UserInfoRequest;
import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import io.tokido.core.identity.spi.ClientStore;
import io.tokido.core.identity.spi.Consent;
import io.tokido.core.identity.spi.ConsentStore;
import io.tokido.core.identity.spi.GrantType;
import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.PersistedGrant;
import io.tokido.core.identity.spi.RefreshTokenUsage;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.TokenStore;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.identity.spi.UserStore;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
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

import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

class IdentityEngineTest {

    @Test
    void builderRejectsMissingIssuer() {
        assertThatNullPointerException().isThrownBy(() ->
                IdentityEngine.builder()
                        .clientStore(stubClientStore())
                        .resourceStore(stubResourceStore())
                        .tokenStore(stubTokenStore())
                        .userStore(stubUserStore())
                        .consentStore(stubConsentStore())
                        .keyStore(stubKeyStore())
                        .tokenSigner(stubSigner())
                        .tokenVerifier(stubTokenVerifier())
                        .build());
    }

    @Test
    void builderRejectsMissingClientStore() {
        assertThatNullPointerException().isThrownBy(() ->
                IdentityEngine.builder()
                        .issuer(URI.create("https://issuer.example/"))
                        .resourceStore(stubResourceStore())
                        .tokenStore(stubTokenStore())
                        .userStore(stubUserStore())
                        .consentStore(stubConsentStore())
                        .keyStore(stubKeyStore())
                        .tokenSigner(stubSigner())
                        .tokenVerifier(stubTokenVerifier())
                        .build());
    }

    @Test
    void builderRejectsMissingTokenVerifier() {
        assertThatNullPointerException().isThrownBy(() ->
                IdentityEngine.builder()
                        .issuer(URI.create("https://issuer.example/"))
                        .clientStore(stubClientStore())
                        .resourceStore(stubResourceStore())
                        .tokenStore(stubTokenStore())
                        .userStore(stubUserStore())
                        .consentStore(stubConsentStore())
                        .keyStore(stubKeyStore())
                        .tokenSigner(stubSigner())
                        .jwksKeyRenderer(stubJwksRenderer())
                        .build());
    }

    @Test
    void buildSucceedsWithAllRequiredSpis() {
        IdentityEngine engine = fullyWiredEngine();
        assertThat(engine).isNotNull();
    }

    @Test
    void buildSucceedsWithCustomClockAndEventSink() {
        IdentityEngine engine = IdentityEngine.builder()
                .issuer(URI.create("https://issuer.example/"))
                .clientStore(stubClientStore())
                .resourceStore(stubResourceStore())
                .tokenStore(stubTokenStore())
                .userStore(stubUserStore())
                .consentStore(stubConsentStore())
                .keyStore(stubKeyStore())
                .tokenSigner(stubSigner())
                .tokenVerifier(stubTokenVerifier())
                .jwksKeyRenderer(stubJwksRenderer())
                .clock(Clock.fixed(Instant.parse("2026-05-01T00:00:00Z"), ZoneOffset.UTC))
                .eventSink((t, ts, a) -> { /* test sink */ })
                .build();
        assertThat(engine).isNotNull();
    }

    @Test
    void unimplementedMethodsThrowUnsupportedAtM2Rc1() {
        IdentityEngine engine = fullyWiredEngine();
        // engine.token is wired at Task 18 — covered by tokenHappyPathDelegatesToHandlerAndReturnsSuccess.
        // engine.userInfo is wired at Task 19 — covered by userInfoHappyPathDelegatesToHandlerAndReturnsSuccess.
        assertThatThrownBy(() -> engine.introspect(new IntrospectionRequest("t", null, "c")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> engine.revoke(new RevocationRequest("t", null, "c")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> engine.endSession(new EndSessionRequest(null, null, null)))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void authorizeHappyPathDelegatesToHandlerAndReturnsRedirect() {
        // Wire an engine with non-stub stores for authorize-relevant SPIs
        // (clientStore, consentStore, tokenStore). Other SPIs remain UoE
        // stubs because the happy path does not consult them.
        Client client = new Client(
                "client-1",
                Set.of(),
                Set.of("https://app.example/cb"),
                Set.of(),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.NONE),
                /* requirePkce */ true,
                /* allowOfflineAccess */ false,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                /* enabled */ true);

        Map<String, Client> clients = new HashMap<>();
        clients.put(client.clientId(), client);
        ClientStore clientStore = new ClientStore() {
            @Override public Client findById(String id) { return clients.get(id); }
            @Override public boolean exists(String id) { return clients.containsKey(id); }
        };

        Consent consent = new Consent("user-1", client.clientId(),
                Set.of("openid"), Instant.parse("2027-01-01T00:00:00Z"));
        ConsentStore consentStore = new ConsentStore() {
            @Override public Consent find(String s, String c) {
                return (consent.subjectId().equals(s) && consent.clientId().equals(c)) ? consent : null;
            }
            @Override public void store(Consent c) { throw new UnsupportedOperationException(); }
            @Override public void remove(String s, String c) { throw new UnsupportedOperationException(); }
        };

        List<PersistedGrant> persisted = new ArrayList<>();
        TokenStore tokenStore = new TokenStore() {
            @Override public void store(PersistedGrant g) { persisted.add(g); }
            @Override public PersistedGrant findByHandle(String h) { throw new UnsupportedOperationException(); }
            @Override public void remove(String h) { throw new UnsupportedOperationException(); }
            @Override public void removeAll(String s, String c) { throw new UnsupportedOperationException(); }
            @Override public void removeAll(String s, String c, GrantType t) { throw new UnsupportedOperationException(); }
        };

        IdentityEngine engine = IdentityEngine.builder()
                .issuer(URI.create("https://issuer.example/"))
                .clientStore(clientStore)
                .resourceStore(stubResourceStore())
                .tokenStore(tokenStore)
                .userStore(stubUserStore())
                .consentStore(consentStore)
                .keyStore(stubKeyStore())
                .tokenSigner(stubSigner())
                .tokenVerifier(stubTokenVerifier())
                .jwksKeyRenderer(stubJwksRenderer())
                .clock(Clock.fixed(Instant.parse("2026-05-02T12:00:00Z"), ZoneOffset.UTC))
                .build();

        AuthorizeRequest req = new AuthorizeRequest(
                client.clientId(), "code", "https://app.example/cb",
                Set.of("openid"),
                "state-x", "n-1",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
                null, Set.of(), null, null, null, null, Map.of());
        AuthenticationState session = new AuthenticationState(
                "user-1", Instant.parse("2026-05-02T11:55:00Z"),
                Set.of("pwd"), null, Map.of());

        AuthorizeResult result = engine.authorize(req, session);

        assertThat(result).isInstanceOf(AuthorizeResult.Redirect.class);
        AuthorizeResult.Redirect redirect = (AuthorizeResult.Redirect) result;
        assertThat(redirect.params())
                .containsKey("code")
                .containsEntry("state", "state-x")
                .containsEntry("iss", "https://issuer.example/");
        assertThat(persisted).hasSize(1);
        assertThat(persisted.get(0).type()).isEqualTo(GrantType.AUTHORIZATION_CODE);
    }

    @Test
    void tokenHappyPathDelegatesToHandlerAndReturnsSuccess() {
        // Wiring smoke test: engine.token(...) must delegate to TokenHandler
        // and return a Success with non-null access/id/refresh tokens. The
        // exhaustive per-branch tests live in TokenHandlerTest; here we only
        // check the engine-to-handler wiring.
        Client client = new Client(
                "client-1",
                Set.of(),
                Set.of("https://app.example/cb"),
                Set.of(),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE),
                Set.of(ClientAuthenticationMethod.NONE),
                /* requirePkce */ true,
                false,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                true);

        Map<String, Client> clients = new HashMap<>();
        clients.put(client.clientId(), client);
        ClientStore clientStore = new ClientStore() {
            @Override public Client findById(String id) { return clients.get(id); }
            @Override public boolean exists(String id) { return clients.containsKey(id); }
        };

        // Pre-seed the token store with a valid (un-consumed) auth code.
        Instant now = Instant.parse("2026-05-02T12:00:00Z");
        AuthorizationCodeData data = new AuthorizationCodeData(
                "n-1",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "S256",
                Set.of("openid"),
                "https://app.example/cb",
                now.minusSeconds(60),
                null);
        PersistedGrant code = new PersistedGrant(
                "CODE", GrantType.AUTHORIZATION_CODE, "user-1", client.clientId(),
                Set.of("openid"),
                now.minusSeconds(60), now.plus(Duration.ofMinutes(10)),
                null, data.toJson());
        Map<String, PersistedGrant> grants = new HashMap<>();
        grants.put(code.handle(), code);
        TokenStore tokenStore = new TokenStore() {
            @Override public void store(PersistedGrant g) { grants.put(g.handle(), g); }
            @Override public PersistedGrant findByHandle(String h) { return grants.get(h); }
            @Override public void remove(String h) { grants.remove(h); }
            @Override public void removeAll(String s, String c) { grants.values().removeIf(g -> g.subjectId().equals(s) && g.clientId().equals(c)); }
            @Override public void removeAll(String s, String c, GrantType t) { grants.values().removeIf(g -> g.subjectId().equals(s) && g.clientId().equals(c) && g.type() == t); }
        };

        UserStore userStore = new UserStore() {
            @Override public io.tokido.core.identity.spi.User findById(String s) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User findByUsername(String u) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.AuthenticationResult authenticate(String u, String c) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User findByExternalProvider(String p, String s) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User createFromExternalProvider(io.tokido.core.identity.spi.BrokeredAuthentication b) { throw new UnsupportedOperationException(); }
            @Override public Set<UserClaim> claims(String s) { return Set.of(); }
        };

        IdentityScope openid = new IdentityScope("openid", null, Set.of("sub"));
        ResourceStore resourceStore = new ResourceStore() {
            @Override public IdentityScope findIdentityScope(String n) { return "openid".equals(n) ? openid : null; }
            @Override public io.tokido.core.identity.spi.ProtectedResource findProtectedResource(String n) { throw new UnsupportedOperationException(); }
            @Override public Set<IdentityScope> findIdentityScopesByName(Set<String> ns) { throw new UnsupportedOperationException(); }
            @Override public Set<io.tokido.core.identity.spi.ProtectedResource> findResourcesByScope(Set<String> ns) { throw new UnsupportedOperationException(); }
        };

        SigningKey key = new SigningKey(
                "test-kid",
                SignatureAlgorithm.RS256,
                new KeyMaterial(new byte[] {0x00}, SignatureAlgorithm.RS256),
                KeyState.ACTIVE,
                now.minusSeconds(3600),
                now.plusSeconds(3600));
        KeyStore keyStore = new KeyStore() {
            @Override public SigningKey activeSigningKey(SignatureAlgorithm a) { return key; }
            @Override public Set<SigningKey> allKeys() { return Set.of(key); }
        };
        TokenSigner tokenSigner = (payload, k) -> "signed." + Integer.toHexString(payload.hashCode());

        IdentityEngine engine = IdentityEngine.builder()
                .issuer(URI.create("https://issuer.example/"))
                .clientStore(clientStore)
                .resourceStore(resourceStore)
                .tokenStore(tokenStore)
                .userStore(userStore)
                .consentStore(stubConsentStore())
                .keyStore(keyStore)
                .tokenSigner(tokenSigner)
                .tokenVerifier(stubTokenVerifier())
                .jwksKeyRenderer(stubJwksRenderer())
                .clock(Clock.fixed(now, ZoneOffset.UTC))
                .build();

        TokenRequest req = new TokenRequest(
                "authorization_code",
                client.clientId(),
                /* clientSecret */ null,
                ClientAuthenticationMethod.NONE,
                "CODE",
                "https://app.example/cb",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                /* refreshToken */ null,
                Set.of(),
                Map.of());

        TokenResult result = engine.token(req);

        assertThat(result).isInstanceOf(TokenResult.Success.class);
        TokenResult.Success ok = (TokenResult.Success) result;
        assertThat(ok.accessToken()).isNotNull();
        assertThat(ok.idToken()).isNotNull();
        assertThat(ok.refreshToken()).isNotBlank();
        assertThat(ok.tokenType()).isEqualTo("Bearer");
        assertThat(ok.expiresIn()).isEqualTo(client.accessTokenLifetime());
    }

    @Test
    void discoveryReturnsDocument() {
        IdentityEngine engine = fullyWiredEngine();
        assertThat(engine.discovery().issuer()).isEqualTo(URI.create("https://issuer.example/"));
    }

    @Test
    void jwksDelegatesToRenderer() {
        // Engine wired with stub key store + stub renderer; assertion is that jwks()
        // ATTEMPTS to delegate (i.e., propagates the stub's UoE rather than the M1
        // engine-level UoE). For richer testing see JwksHandlerTest.
        IdentityEngine engine = fullyWiredEngine();
        assertThatThrownBy(engine::jwks).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void builderRejectsMissingJwksKeyRenderer() {
        assertThatNullPointerException().isThrownBy(() ->
                IdentityEngine.builder()
                        .issuer(URI.create("https://issuer.example/"))
                        .clientStore(stubClientStore())
                        .resourceStore(stubResourceStore())
                        .tokenStore(stubTokenStore())
                        .userStore(stubUserStore())
                        .consentStore(stubConsentStore())
                        .keyStore(stubKeyStore())
                        .tokenSigner(stubSigner())
                        .tokenVerifier(stubTokenVerifier())
                        .build());
    }

    @Test
    void userInfoHappyPathDelegatesToHandlerAndReturnsSuccess() {
        // Wiring smoke test: engine.userInfo(...) must delegate to UserInfoHandler
        // and return a Success with the sub claim and the user's claim set. The
        // exhaustive per-branch tests live in UserInfoHandlerTest; here we only
        // check the engine-to-handler wiring.
        UserStore userStore = new UserStore() {
            @Override public io.tokido.core.identity.spi.User findById(String s) {
                return "alice".equals(s)
                        ? new io.tokido.core.identity.spi.User("alice", "alice", true, Map.of())
                        : null;
            }
            @Override public io.tokido.core.identity.spi.User findByUsername(String u) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.AuthenticationResult authenticate(String u, String c) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User findByExternalProvider(String p, String s) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User createFromExternalProvider(io.tokido.core.identity.spi.BrokeredAuthentication b) { throw new UnsupportedOperationException(); }
            @Override public Set<UserClaim> claims(String s) {
                return "alice".equals(s) ? Set.of(new UserClaim("name", "Alice")) : Set.of();
            }
        };
        TokenVerifier verifier = (token, ks) -> Map.of("sub", "alice", "iss", "https://issuer.example/");

        IdentityEngine engine = IdentityEngine.builder()
                .issuer(URI.create("https://issuer.example/"))
                .clientStore(stubClientStore())
                .resourceStore(stubResourceStore())
                .tokenStore(stubTokenStore())
                .userStore(userStore)
                .consentStore(stubConsentStore())
                .keyStore(stubKeyStore())
                .tokenSigner(stubSigner())
                .tokenVerifier(verifier)
                .jwksKeyRenderer(stubJwksRenderer())
                .build();

        io.tokido.core.identity.protocol.UserInfoResult result =
                engine.userInfo(new UserInfoRequest("any-token"));

        assertThat(result).isInstanceOf(io.tokido.core.identity.protocol.UserInfoResult.Success.class);
        io.tokido.core.identity.protocol.UserInfoResult.Success ok =
                (io.tokido.core.identity.protocol.UserInfoResult.Success) result;
        assertThat(ok.subjectId()).isEqualTo("alice");
        assertThat(ok.claims()).containsExactly(new UserClaim("name", "Alice"));
    }

    @Test
    void noopEventSinkAcceptsEvents() {
        EventSink sink = EventSink.noop();
        sink.emit("test", Instant.now(), Map.of("k", "v"));
        // No exception, no observable behavior. Good.
    }

    private IdentityEngine fullyWiredEngine() {
        return IdentityEngine.builder()
                .issuer(URI.create("https://issuer.example/"))
                .clientStore(stubClientStore())
                .resourceStore(stubResourceStore())
                .tokenStore(stubTokenStore())
                .userStore(stubUserStore())
                .consentStore(stubConsentStore())
                .keyStore(stubKeyStore())
                .tokenSigner(stubSigner())
                .tokenVerifier(stubTokenVerifier())
                .jwksKeyRenderer(stubJwksRenderer())
                .build();
    }

    // ---- minimal SPI stubs (every method throws UoE — engine never invokes them at M1) ----

    private ClientStore stubClientStore() {
        return new ClientStore() {
            @Override public io.tokido.core.identity.spi.Client findById(String id) { throw new UnsupportedOperationException(); }
            @Override public boolean exists(String id) { throw new UnsupportedOperationException(); }
        };
    }

    private ResourceStore stubResourceStore() {
        return new ResourceStore() {
            @Override public io.tokido.core.identity.spi.IdentityScope findIdentityScope(String n) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.ProtectedResource findProtectedResource(String n) { throw new UnsupportedOperationException(); }
            @Override public Set<io.tokido.core.identity.spi.IdentityScope> findIdentityScopesByName(Set<String> ns) { throw new UnsupportedOperationException(); }
            @Override public Set<io.tokido.core.identity.spi.ProtectedResource> findResourcesByScope(Set<String> ns) { throw new UnsupportedOperationException(); }
        };
    }

    private TokenStore stubTokenStore() {
        return new TokenStore() {
            @Override public void store(io.tokido.core.identity.spi.PersistedGrant g) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.PersistedGrant findByHandle(String h) { throw new UnsupportedOperationException(); }
            @Override public void remove(String h) { throw new UnsupportedOperationException(); }
            @Override public void removeAll(String s, String c) { throw new UnsupportedOperationException(); }
            @Override public void removeAll(String s, String c, io.tokido.core.identity.spi.GrantType t) { throw new UnsupportedOperationException(); }
        };
    }

    private UserStore stubUserStore() {
        return new UserStore() {
            @Override public io.tokido.core.identity.spi.User findById(String s) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User findByUsername(String u) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.AuthenticationResult authenticate(String u, String c) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User findByExternalProvider(String p, String s) { throw new UnsupportedOperationException(); }
            @Override public io.tokido.core.identity.spi.User createFromExternalProvider(io.tokido.core.identity.spi.BrokeredAuthentication b) { throw new UnsupportedOperationException(); }
            @Override public Set<io.tokido.core.identity.spi.UserClaim> claims(String s) { throw new UnsupportedOperationException(); }
        };
    }

    private ConsentStore stubConsentStore() {
        return new ConsentStore() {
            @Override public io.tokido.core.identity.spi.Consent find(String s, String c) { throw new UnsupportedOperationException(); }
            @Override public void store(io.tokido.core.identity.spi.Consent c) { throw new UnsupportedOperationException(); }
            @Override public void remove(String s, String c) { throw new UnsupportedOperationException(); }
        };
    }

    private KeyStore stubKeyStore() {
        return new KeyStore() {
            @Override public SigningKey activeSigningKey(SignatureAlgorithm a) { throw new UnsupportedOperationException(); }
            @Override public Set<SigningKey> allKeys() { throw new UnsupportedOperationException(); }
        };
    }

    private TokenSigner stubSigner() {
        return (payload, key) -> { throw new UnsupportedOperationException(); };
    }

    private TokenVerifier stubTokenVerifier() {
        return (token, keyStore) -> Map.of();
    }

    private io.tokido.core.identity.key.JwksKeyRenderer stubJwksRenderer() {
        return key -> { throw new UnsupportedOperationException("test stub"); };
    }
}
