package io.tokido.core.identity.engine;

import io.tokido.core.identity.key.JwksKeyRenderer;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.protocol.AuthenticationState;
import io.tokido.core.identity.protocol.AuthorizeRequest;
import io.tokido.core.identity.protocol.AuthorizeResult;
import io.tokido.core.identity.protocol.DiscoveryDocument;
import io.tokido.core.identity.protocol.EndSessionRequest;
import io.tokido.core.identity.protocol.EndSessionResult;
import io.tokido.core.identity.protocol.IntrospectionRequest;
import io.tokido.core.identity.protocol.IntrospectionResult;
import io.tokido.core.identity.protocol.JsonWebKeySet;
import io.tokido.core.identity.protocol.RevocationRequest;
import io.tokido.core.identity.protocol.RevocationResult;
import io.tokido.core.identity.protocol.TokenRequest;
import io.tokido.core.identity.protocol.TokenResult;
import io.tokido.core.identity.protocol.UserInfoRequest;
import io.tokido.core.identity.protocol.UserInfoResult;
import io.tokido.core.identity.spi.ClientStore;
import io.tokido.core.identity.spi.ConsentStore;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.TokenStore;
import io.tokido.core.identity.spi.UserStore;
import org.apiguardian.api.API;

import java.net.URI;
import java.time.Clock;
import java.util.Objects;

/**
 * The pure-function OIDC protocol engine.
 *
 * <p>Build with {@link #builder()}, supplying a SPI implementation for each
 * storage concern, plus a {@link TokenSigner} (typically
 * {@code NimbusTokenSigner} from {@code tokido-core-identity-jwt}, M2+).
 *
 * <p>At M1 every method throws {@link UnsupportedOperationException}; M2
 * lands the real implementations.
 *
 * <p>Thread-safety: the engine itself is stateless; safety follows the SPI
 * implementations supplied to the builder.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public final class IdentityEngine {

    private final URI issuer;
    private final ClientStore clientStore;
    private final ResourceStore resourceStore;
    private final TokenStore tokenStore;
    private final UserStore userStore;
    private final ConsentStore consentStore;
    private final KeyStore keyStore;
    private final TokenSigner tokenSigner;
    private final JwksKeyRenderer jwksKeyRenderer;
    private final Clock clock;
    private final EventSink eventSink;

    private IdentityEngine(Builder b) {
        this.issuer = Objects.requireNonNull(b.issuer, "issuer");
        this.clientStore = Objects.requireNonNull(b.clientStore, "clientStore");
        this.resourceStore = Objects.requireNonNull(b.resourceStore, "resourceStore");
        this.tokenStore = Objects.requireNonNull(b.tokenStore, "tokenStore");
        this.userStore = Objects.requireNonNull(b.userStore, "userStore");
        this.consentStore = Objects.requireNonNull(b.consentStore, "consentStore");
        this.keyStore = Objects.requireNonNull(b.keyStore, "keyStore");
        this.tokenSigner = Objects.requireNonNull(b.tokenSigner, "tokenSigner");
        this.jwksKeyRenderer = Objects.requireNonNull(b.jwksKeyRenderer, "jwksKeyRenderer");
        this.clock = b.clock != null ? b.clock : Clock.systemUTC();
        this.eventSink = b.eventSink != null ? b.eventSink : EventSink.noop();
    }

    /**
     * Open a new engine builder.
     *
     * @return a fresh builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Process an OIDC authorize request.
     *
     * @param req   the authorize request
     * @param state browser-session auth state
     * @return one of the {@link AuthorizeResult} variants
     */
    public AuthorizeResult authorize(AuthorizeRequest req, AuthenticationState state) {
        return new io.tokido.core.identity.engine.authorize.AuthorizeHandler(
                issuer, clock, clientStore, consentStore, resourceStore, tokenStore)
                .handle(req, state);
    }

    /**
     * Process an OAuth/OIDC token request.
     *
     * @param req the token request
     * @return one of the {@link TokenResult} variants
     */
    public TokenResult token(TokenRequest req) {
        return new io.tokido.core.identity.engine.token.TokenHandler(
                issuer, clientStore, tokenStore, userStore, resourceStore,
                keyStore, tokenSigner, clock, eventSink)
                .handle(req);
    }

    /**
     * Process a UserInfo request.
     *
     * @param req the userinfo request
     * @return one of the {@link UserInfoResult} variants
     */
    public UserInfoResult userInfo(UserInfoRequest req) {
        throw new UnsupportedOperationException("IdentityEngine.userInfo lands at M2");
    }

    /**
     * Build the discovery document.
     *
     * @return the OIDC discovery document
     */
    public DiscoveryDocument discovery() {
        return new io.tokido.core.identity.engine.discovery.DiscoveryHandler(issuer).build();
    }

    /**
     * Build the JWKS document.
     *
     * @return the JWK set served at the JWKS endpoint
     */
    public JsonWebKeySet jwks() {
        return new io.tokido.core.identity.engine.jwks.JwksHandler(keyStore, jwksKeyRenderer).build();
    }

    /**
     * Process an RFC 7662 introspection request.
     *
     * @param req the introspection request
     * @return one of the {@link IntrospectionResult} variants
     */
    public IntrospectionResult introspect(IntrospectionRequest req) {
        throw new UnsupportedOperationException("IdentityEngine.introspect lands at M2");
    }

    /**
     * Process an RFC 7009 revocation request.
     *
     * @param req the revocation request
     * @return one of the {@link RevocationResult} variants
     */
    public RevocationResult revoke(RevocationRequest req) {
        throw new UnsupportedOperationException("IdentityEngine.revoke lands at M2");
    }

    /**
     * Process an OIDC end-session request.
     *
     * @param req the end-session request
     * @return one of the {@link EndSessionResult} variants
     */
    public EndSessionResult endSession(EndSessionRequest req) {
        throw new UnsupportedOperationException("IdentityEngine.endSession lands at M2");
    }

    /** Mutable builder. Each field has a fluent setter. */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    public static final class Builder {
        private URI issuer;
        private ClientStore clientStore;
        private ResourceStore resourceStore;
        private TokenStore tokenStore;
        private UserStore userStore;
        private ConsentStore consentStore;
        private KeyStore keyStore;
        private TokenSigner tokenSigner;
        private JwksKeyRenderer jwksKeyRenderer;
        private Clock clock;
        private EventSink eventSink;

        private Builder() {}

        /**
         * @param v issuer URI; required
         * @return this builder
         */
        public Builder issuer(URI v)                   { this.issuer = v; return this; }

        /**
         * @param v client store; required
         * @return this builder
         */
        public Builder clientStore(ClientStore v)      { this.clientStore = v; return this; }

        /**
         * @param v resource store; required
         * @return this builder
         */
        public Builder resourceStore(ResourceStore v)  { this.resourceStore = v; return this; }

        /**
         * @param v token store; required
         * @return this builder
         */
        public Builder tokenStore(TokenStore v)        { this.tokenStore = v; return this; }

        /**
         * @param v user store; required
         * @return this builder
         */
        public Builder userStore(UserStore v)          { this.userStore = v; return this; }

        /**
         * @param v consent store; required
         * @return this builder
         */
        public Builder consentStore(ConsentStore v)    { this.consentStore = v; return this; }

        /**
         * @param v key store; required
         * @return this builder
         */
        public Builder keyStore(KeyStore v)            { this.keyStore = v; return this; }

        /**
         * @param v token signer; required
         * @return this builder
         */
        public Builder tokenSigner(TokenSigner v)      { this.tokenSigner = v; return this; }

        /**
         * @param v JWK renderer; required
         * @return this builder
         */
        public Builder jwksKeyRenderer(JwksKeyRenderer v) { this.jwksKeyRenderer = v; return this; }

        /**
         * @param v clock; optional (defaults to {@link Clock#systemUTC()})
         * @return this builder
         */
        public Builder clock(Clock v)                  { this.clock = v; return this; }

        /**
         * @param v event sink; optional (defaults to {@link EventSink#noop()})
         * @return this builder
         */
        public Builder eventSink(EventSink v)          { this.eventSink = v; return this; }

        /**
         * Build the engine.
         *
         * @return a newly built IdentityEngine
         * @throws NullPointerException if any required SPI is missing
         */
        public IdentityEngine build() { return new IdentityEngine(this); }
    }
}
