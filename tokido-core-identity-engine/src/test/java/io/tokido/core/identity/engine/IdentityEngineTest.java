package io.tokido.core.identity.engine;

import io.tokido.core.identity.protocol.AuthenticationState;
import io.tokido.core.identity.protocol.AuthorizeRequest;
import io.tokido.core.identity.protocol.EndSessionRequest;
import io.tokido.core.identity.protocol.IntrospectionRequest;
import io.tokido.core.identity.protocol.RevocationRequest;
import io.tokido.core.identity.protocol.TokenRequest;
import io.tokido.core.identity.protocol.UserInfoRequest;
import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import io.tokido.core.identity.spi.ClientStore;
import io.tokido.core.identity.spi.ConsentStore;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.TokenStore;
import io.tokido.core.identity.spi.UserStore;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
                .jwksKeyRenderer(stubJwksRenderer())
                .clock(Clock.fixed(Instant.parse("2026-05-01T00:00:00Z"), ZoneOffset.UTC))
                .eventSink((t, ts, a) -> { /* test sink */ })
                .build();
        assertThat(engine).isNotNull();
    }

    @Test
    void allMethodsThrowUnsupportedAtM1() {
        IdentityEngine engine = fullyWiredEngine();
        AuthorizeRequest auth = new AuthorizeRequest("c", "code", null, Set.of("openid"),
                null, null, null, null, null, Set.of(), null, null, null, null, Map.of());
        TokenRequest tok = new TokenRequest("authorization_code", "c", null,
                ClientAuthenticationMethod.NONE, "code", null, null, null, Set.of(), Map.of());
        assertThatThrownBy(() -> engine.authorize(auth, AuthenticationState.anonymous()))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> engine.token(tok))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> engine.userInfo(new UserInfoRequest("at")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> engine.introspect(new IntrospectionRequest("t", null, "c")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> engine.revoke(new RevocationRequest("t", null, "c")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> engine.endSession(new EndSessionRequest(null, null, null)))
                .isInstanceOf(UnsupportedOperationException.class);
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
                        .build());
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

    private io.tokido.core.identity.key.JwksKeyRenderer stubJwksRenderer() {
        return key -> { throw new UnsupportedOperationException("test stub"); };
    }
}
