package io.tokido.core.identity.conformance;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.tokido.core.identity.engine.IdentityEngine;
import io.tokido.core.identity.engine.shared.JsonWriter;
import io.tokido.core.identity.jwt.InMemoryKeyStore;
import io.tokido.core.identity.jwt.JwksRenderer;
import io.tokido.core.identity.jwt.NimbusTokenSigner;
import io.tokido.core.identity.jwt.NimbusTokenVerifier;
import io.tokido.core.identity.protocol.AuthenticationState;
import io.tokido.core.identity.protocol.AuthorizeRequest;
import io.tokido.core.identity.protocol.AuthorizeResult;
import io.tokido.core.identity.protocol.DiscoveryDocument;
import io.tokido.core.identity.protocol.JsonWebKey;
import io.tokido.core.identity.protocol.JsonWebKeySet;
import io.tokido.core.identity.protocol.TokenRequest;
import io.tokido.core.identity.protocol.TokenResult;
import io.tokido.core.identity.protocol.UserInfoRequest;
import io.tokido.core.identity.protocol.UserInfoResult;
import io.tokido.core.identity.spi.AuthenticationResult;
import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import io.tokido.core.identity.spi.ClientSecret;
import io.tokido.core.identity.spi.Consent;
import io.tokido.core.identity.spi.GrantType;
import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.RefreshTokenUsage;
import io.tokido.core.identity.spi.User;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.test.identity.MapClientStore;
import io.tokido.core.test.identity.MapConsentStore;
import io.tokido.core.test.identity.MapResourceStore;
import io.tokido.core.test.identity.MapTokenStore;
import io.tokido.core.test.identity.MapUserStore;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-process HTTP server that wires the OIDC suite to a fully-built
 * {@link IdentityEngine}. Replaces the M0/M1 {@code StubAdapter} (which
 * returned 501 for every endpoint) at M2.RC1.
 *
 * <p>The adapter mounts the routes the OIDF basic-certification plan exercises:
 * {@code /.well-known/openid-configuration}, {@code /jwks},
 * {@code /authorize}, {@code /token}, {@code /userinfo}. Endpoints not yet
 * implemented by the engine ({@code /introspect}, {@code /revoke},
 * {@code /end_session}) keep returning 501 so the suite's discovery probe
 * does not flag stale advertisements.
 *
 * <p><b>Conformance-test scaffolding shortcuts</b> (clearly NOT production
 * behaviour):
 * <ul>
 *   <li><b>Auto-login.</b> When the engine returns
 *       {@link AuthorizeResult.LoginRequired} the adapter authenticates as the
 *       seed user {@code alice}/{@code password123} without rendering a form.
 *       The OIDF basic plan is testing protocol behaviour, not login UX. A
 *       production adapter would render an HTML login form.</li>
 *   <li><b>Auto-consent.</b> When the engine returns
 *       {@link AuthorizeResult.ConsentRequired} the adapter persists a
 *       {@link Consent} covering the requested scopes and re-runs the
 *       authorize call once. A production adapter would render a consent
 *       UI.</li>
 *   <li><b>Permissive redirect URIs.</b> The seeded clients register a
 *       superset of redirect URIs the suite is known to use. A production
 *       deployment would register only the exact URI the relying party is
 *       deployed at.</li>
 * </ul>
 *
 * <p>The issuer hostname defaults to {@code host.docker.internal} so the
 * dockerised OIDF suite can reach the SUT via Docker's host gateway. Pure
 * unit tests pass {@code "localhost"} via {@link #start(int, String)} so the
 * test JVM can talk to itself via loopback.
 */
final class EngineAdapter {

    private static final SecureRandom RNG = new SecureRandom();

    /**
     * Diagnostic flag for OIDF debugging. When {@code tokido.conformance.debug}
     * is set the adapter prints one line to {@code System.err} per inbound
     * request and per outbound response, with method, path, decoded query
     * string, and the response status. Off by default to keep test output
     * clean.
     */
    private static final boolean DEBUG = Boolean.getBoolean("tokido.conformance.debug");

    /** Seed username for the auto-login shortcut. */
    static final String SEED_USERNAME = "alice";
    /** Seed password for the auto-login shortcut. */
    static final String SEED_PASSWORD = "password123";
    /** Subject id of the seed user. */
    static final String SEED_SUBJECT_ID = "sub-alice";

    /** First seeded client id (matches {@code OidcConformanceIT}'s plan config). */
    static final String CLIENT_ID = "tokido_m0_client";
    /** First seeded client secret. */
    static final String CLIENT_SECRET = "tokido_m0_secret";
    /** Second seeded client id (the plan's {@code client2}). */
    static final String CLIENT2_ID = "tokido_m0_client2";
    /** Second seeded client secret. */
    static final String CLIENT2_SECRET = "tokido_m0_secret2";

    private static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofMinutes(15);
    private static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofDays(30);
    private static final Duration CONSENT_LIFETIME = Duration.ofDays(30);

    private final HttpServer server;
    private final IdentityEngine engine;
    private final MapConsentStore consentStore;
    private final MapUserStore userStore;
    /** Active sessions keyed by the {@code SID} cookie value. */
    private final ConcurrentHashMap<String, AuthenticationState> sessions = new ConcurrentHashMap<>();

    private EngineAdapter(HttpServer server,
                          IdentityEngine engine,
                          MapConsentStore consentStore,
                          MapUserStore userStore) {
        this.server = server;
        this.engine = engine;
        this.consentStore = consentStore;
        this.userStore = userStore;
    }

    /**
     * Start the adapter on the requested port using {@code host.docker.internal}
     * as the discovery hostname. This is the form the OIDF docker container
     * uses to reach the SUT.
     *
     * @param requestedPort 0 for any free port, otherwise a fixed port number
     * @return started adapter; call {@link #stop()} when done
     */
    static EngineAdapter start(int requestedPort) throws IOException {
        return start(requestedPort, "host.docker.internal");
    }

    /**
     * Start the adapter on the requested port with an explicit issuer hostname.
     *
     * @param requestedPort 0 for any free port, otherwise a fixed port number
     * @param issuerHost    hostname to advertise in the discovery document
     * @return started adapter; call {@link #stop()} when done
     */
    static EngineAdapter start(int requestedPort, String issuerHost) throws IOException {
        Objects.requireNonNull(issuerHost, "issuerHost");
        HttpServer server = HttpServer.create(new InetSocketAddress(requestedPort), 0);
        int port = server.getAddress().getPort();
        URI issuer = URI.create("http://" + issuerHost + ":" + port + "/");

        MapClientStore clientStore = new MapClientStore(seedClients());
        MapResourceStore resourceStore = new MapResourceStore(seedScopes(), Set.of());
        MapTokenStore tokenStore = new MapTokenStore(Clock.systemUTC());
        MapUserStore userStore = seedUserStore();
        MapConsentStore consentStore = new MapConsentStore();
        InMemoryKeyStore keyStore = new InMemoryKeyStore();

        IdentityEngine engine = IdentityEngine.builder()
                .issuer(issuer)
                .clientStore(clientStore)
                .resourceStore(resourceStore)
                .tokenStore(tokenStore)
                .userStore(userStore)
                .consentStore(consentStore)
                .keyStore(keyStore)
                .tokenSigner(new NimbusTokenSigner())
                .tokenVerifier(new NimbusTokenVerifier())
                .jwksKeyRenderer(new JwksRenderer())
                .build();

        EngineAdapter adapter = new EngineAdapter(server, engine, consentStore, userStore);
        adapter.installRoutes();
        server.start();
        return adapter;
    }

    /** @return the local port the server is bound to */
    int port() {
        return server.getAddress().getPort();
    }

    /** Stop the server immediately, dropping any in-flight requests. */
    void stop() {
        server.stop(0);
    }

    // ── route installation ──────────────────────────────────────────────────

    private void installRoutes() {
        server.createContext("/.well-known/openid-configuration", this::handleDiscovery);
        server.createContext("/jwks", this::handleJwks);
        server.createContext("/authorize", this::handleAuthorize);
        server.createContext("/token", this::handleToken);
        server.createContext("/userinfo", this::handleUserInfo);
        // Endpoints not yet wired to the engine; advertise the engine's
        // discovery doc faithfully (which omits them) but keep the legacy 501
        // for any suite probe that hits these paths regardless.
        server.createContext("/introspect", EngineAdapter::handle501);
        server.createContext("/revoke", EngineAdapter::handle501);
        server.createContext("/end_session", EngineAdapter::handle501);
        server.createContext("/", EngineAdapter::handle404);
    }

    // ── /.well-known/openid-configuration ───────────────────────────────────

    private void handleDiscovery(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendStatus(exchange, 405);
            return;
        }
        DiscoveryDocument doc = engine.discovery();
        StringBuilder sb = new StringBuilder(512);
        sb.append('{');
        boolean first = true;
        first = JsonWriter.appendRequiredStringField(sb, "issuer", doc.issuer().toString(), first);
        first = JsonWriter.appendRequiredStringField(sb, "authorization_endpoint",
                doc.authorizationEndpoint().toString(), first);
        first = JsonWriter.appendRequiredStringField(sb, "token_endpoint",
                doc.tokenEndpoint().toString(), first);
        if (doc.userinfoEndpoint() != null) {
            first = JsonWriter.appendRequiredStringField(sb, "userinfo_endpoint",
                    doc.userinfoEndpoint().toString(), first);
        }
        first = JsonWriter.appendRequiredStringField(sb, "jwks_uri", doc.jwksUri().toString(), first);
        first = JsonWriter.appendOptionalStringArrayField(sb, "response_types_supported",
                doc.responseTypesSupported(), first);
        first = JsonWriter.appendOptionalStringArrayField(sb, "grant_types_supported",
                doc.grantTypesSupported(), first);
        first = JsonWriter.appendOptionalStringArrayField(sb, "subject_types_supported",
                doc.subjectTypesSupported(), first);
        first = JsonWriter.appendOptionalStringArrayField(sb, "id_token_signing_alg_values_supported",
                doc.idTokenSigningAlgValuesSupported(), first);
        first = JsonWriter.appendOptionalStringArrayField(sb, "scopes_supported",
                doc.scopesSupported(), first);
        first = JsonWriter.appendOptionalStringArrayField(sb, "token_endpoint_auth_methods_supported",
                doc.tokenEndpointAuthMethodsSupported(), first);
        first = JsonWriter.appendOptionalStringArrayField(sb, "claims_supported",
                doc.claimsSupported(), first);
        // Hard-code the PKCE methods we support so the suite's probe finds them
        // even though the engine's DiscoveryDocument record does not have a
        // dedicated field for them yet (M3 will add it).
        JsonWriter.appendOptionalStringArrayField(sb, "code_challenge_methods_supported",
                Set.of("S256", "plain"), first);
        sb.append('}');
        sendJson(exchange, 200, sb.toString());
    }

    // ── /jwks ───────────────────────────────────────────────────────────────

    private void handleJwks(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendStatus(exchange, 405);
            return;
        }
        JsonWebKeySet keys = engine.jwks();
        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"keys\":[");
        boolean firstKey = true;
        for (JsonWebKey jwk : keys.keys()) {
            if (!firstKey) sb.append(',');
            renderJwk(sb, jwk);
            firstKey = false;
        }
        sb.append("]}");
        sendJson(exchange, 200, sb.toString());
    }

    /**
     * Render one {@link JsonWebKey} as a JSON object. Mandatory fields are
     * emitted first, then any additional fields (e.g., {@code n}, {@code e}
     * for RSA) iterated from the additional-parameters map.
     */
    private static void renderJwk(StringBuilder sb, JsonWebKey jwk) {
        sb.append('{');
        boolean first = true;
        first = JsonWriter.appendRequiredStringField(sb, "kty", jwk.kty(), first);
        first = JsonWriter.appendRequiredStringField(sb, "kid", jwk.kid(), first);
        first = JsonWriter.appendOptionalStringField(sb, "use", jwk.use(), first);
        first = JsonWriter.appendOptionalStringField(sb, "alg", jwk.alg(), first);
        for (Map.Entry<String, Object> e : jwk.additionalParameters().entrySet()) {
            Object v = e.getValue();
            if (v == null) continue;
            if (!first) sb.append(',');
            sb.append('"').append(e.getKey()).append("\":");
            if (v instanceof Number n) {
                sb.append(n);
            } else {
                JsonWriter.appendString(sb, v.toString());
            }
            first = false;
        }
        sb.append('}');
    }

    // ── /authorize ──────────────────────────────────────────────────────────

    private void handleAuthorize(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQueryString(exchange.getRequestURI().getRawQuery());
        AuthorizeRequest req = buildAuthorizeRequest(params);
        AuthenticationState session = readSession(exchange);

        AuthorizeResult result = engine.authorize(req, session);
        // Auto-login + auto-consent: at most one retry each, in that order.
        if (result instanceof AuthorizeResult.LoginRequired) {
            session = autoLogin(exchange);
            result = engine.authorize(req, session);
        }
        if (result instanceof AuthorizeResult.ConsentRequired cr) {
            consentStore.store(new Consent(
                    session.subjectId(),
                    req.clientId(),
                    cr.requestedScopes(),
                    Instant.now().plus(CONSENT_LIFETIME)));
            result = engine.authorize(req, session);
        }

        if (result instanceof AuthorizeResult.Redirect redirect) {
            // EngineAdapter relies on the engine's AuthorizeHandler having
            // already baked `redirect.params()` into `redirect.redirectUri()`
            // (see AuthorizeHandler.handle() — appendQuery is applied before
            // constructing the Redirect record). If the engine contract
            // changes to return params separately, attach them here via
            // appendQuery.
            exchange.getResponseHeaders().add("Location", redirect.redirectUri().toString());
            sendStatus(exchange, 302);
            return;
        }
        if (result instanceof AuthorizeResult.Error err) {
            // Per RFC 6749 §4.1.2.1, redirect-back-to-client is only valid when
            // the redirect_uri itself was valid. The engine signals that by
            // setting state==null when redirect_uri validation failed (see
            // AuthorizeHandler comment for the same constraint).
            if (err.state() != null && req.redirectUri() != null) {
                Map<String, String> errParams = new LinkedHashMap<>();
                errParams.put("error", err.code());
                if (err.description() != null) errParams.put("error_description", err.description());
                errParams.put("state", err.state());
                exchange.getResponseHeaders().add("Location",
                        appendQuery(req.redirectUri(), errParams));
                sendStatus(exchange, 302);
                return;
            }
            sendText(exchange, 400,
                    "authorize error: " + err.code()
                            + (err.description() == null ? "" : " — " + err.description()));
            return;
        }
        if (result instanceof AuthorizeResult.MfaRequired) {
            // M4 work; the OIDF basic-cert plan does not exercise step-up.
            sendStatus(exchange, 500);
            return;
        }
        if (result instanceof AuthorizeResult.LoginRequired
                || result instanceof AuthorizeResult.ConsentRequired) {
            // Should not happen — auto-login + auto-consent already retried.
            sendText(exchange, 500, "auto-login/consent retry exhausted");
            return;
        }
        sendStatus(exchange, 500);
    }

    private static AuthorizeRequest buildAuthorizeRequest(Map<String, String> p) {
        Set<String> scopes = parseScopeList(p.get("scope"));
        Set<String> acrs = parseScopeList(p.get("acr_values"));
        Long maxAge = null;
        String maxAgeRaw = p.get("max_age");
        if (maxAgeRaw != null) {
            try { maxAge = Long.parseLong(maxAgeRaw); } catch (NumberFormatException ignored) { }
        }
        String clientId = p.getOrDefault("client_id", "");
        // AuthorizeRequest demands a non-blank clientId; fall back to a
        // deliberately-bogus marker so the engine returns invalid_client and
        // the adapter renders a 400 rather than crashing on construction.
        if (clientId.isBlank()) clientId = "__missing_client_id__";
        return new AuthorizeRequest(
                clientId,
                p.get("response_type"),
                p.get("redirect_uri"),
                scopes,
                p.get("state"),
                p.get("nonce"),
                p.get("code_challenge"),
                p.get("code_challenge_method"),
                p.get("response_mode"),
                acrs,
                maxAge,
                p.get("prompt"),
                p.get("login_hint"),
                p.get("ui_locales"),
                Map.of());
    }

    /**
     * Auto-login as the seed user. Sets a session cookie on the response and
     * returns the corresponding {@link AuthenticationState}. The cookie lets
     * later requests in the same browser-flow re-use the session without
     * re-authenticating.
     */
    private AuthenticationState autoLogin(HttpExchange exchange) {
        AuthenticationResult auth = userStore.authenticate(SEED_USERNAME, SEED_PASSWORD);
        if (!(auth instanceof AuthenticationResult.Success success)) {
            // Should never happen — the seed is hard-coded above.
            throw new IllegalStateException("seed user authentication failed: " + auth);
        }
        AuthenticationState state = new AuthenticationState(
                success.user().subjectId(),
                Instant.now(),
                Set.of("pwd"),
                null,
                Map.of());
        String sid = randomToken(16);
        sessions.put(sid, state);
        exchange.getResponseHeaders().add("Set-Cookie",
                "SID=" + sid + "; Path=/; HttpOnly");
        return state;
    }

    private AuthenticationState readSession(HttpExchange exchange) {
        List<String> cookies = exchange.getRequestHeaders().get("Cookie");
        if (cookies == null) return AuthenticationState.anonymous();
        for (String header : cookies) {
            for (String pair : header.split(";")) {
                String[] kv = pair.trim().split("=", 2);
                if (kv.length == 2 && "SID".equals(kv[0])) {
                    AuthenticationState state = sessions.get(kv[1]);
                    if (state != null) return state;
                }
            }
        }
        return AuthenticationState.anonymous();
    }

    // ── /token ──────────────────────────────────────────────────────────────

    private void handleToken(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendStatus(exchange, 405);
            return;
        }
        Map<String, String> form = parseFormBody(exchange.getRequestBody());
        String basicAuthHeader = exchange.getRequestHeaders().getFirst("Authorization");

        String clientId;
        String clientSecret;
        ClientAuthenticationMethod authMethod;
        // RFC 7235 §2.1 / RFC 7617 require case-insensitive scheme matching.
        if (basicAuthHeader != null && basicAuthHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            String decoded = new String(
                    Base64.getDecoder().decode(basicAuthHeader.substring(6).trim()),
                    StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) {
                writeInvalidClient(exchange, "malformed Basic credentials");
                return;
            }
            clientId = decoded.substring(0, colon);
            clientSecret = decoded.substring(colon + 1);
            authMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (form.get("client_secret") != null) {
            clientId = form.getOrDefault("client_id", "");
            clientSecret = form.get("client_secret");
            authMethod = ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else {
            clientId = form.getOrDefault("client_id", "");
            clientSecret = null;
            authMethod = ClientAuthenticationMethod.NONE;
        }
        if (clientId == null || clientId.isBlank()) {
            writeInvalidClient(exchange, "client_id is required");
            return;
        }

        String grantType = form.get("grant_type");
        if (grantType == null || grantType.isBlank()) {
            sendJson(exchange, 400, errorJson("invalid_request", "grant_type is required"));
            return;
        }

        TokenRequest req;
        try {
            req = new TokenRequest(
                    grantType,
                    clientId,
                    clientSecret,
                    authMethod,
                    form.get("code"),
                    form.get("redirect_uri"),
                    form.get("code_verifier"),
                    form.get("refresh_token"),
                    parseScopeList(form.get("scope")),
                    Map.of());
        } catch (RuntimeException e) {
            sendJson(exchange, 400, errorJson("invalid_request", e.getMessage()));
            return;
        }

        TokenResult result = engine.token(req);
        if (result instanceof TokenResult.Success ok) {
            sendJson(exchange, 200, successJson(ok));
        } else if (result instanceof TokenResult.Error err) {
            writeTokenError(exchange, err);
        } else {
            sendJson(exchange, 500, errorJson("server_error", "unexpected result"));
        }
    }

    /**
     * Render a token-endpoint error per RFC 6749 §5.2: {@code invalid_client}
     * gets 401 with {@code WWW-Authenticate: Basic} (the suite occasionally
     * fuzzes credentials in negative tests); everything else stays 400.
     */
    private static void writeTokenError(HttpExchange exchange, TokenResult.Error err) throws IOException {
        if ("invalid_client".equals(err.code())) {
            writeInvalidClient(exchange, err.description());
            return;
        }
        sendJson(exchange, 400, errorJson(err.code(), err.description()));
    }

    /**
     * Render a 401 invalid_client response with the WWW-Authenticate header
     * RFC 6749 §5.2 says the server "MAY include" — we always do, since the
     * OIDF certification suite checks for it on Basic-auth failures.
     */
    private static void writeInvalidClient(HttpExchange exchange, String description) throws IOException {
        exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"tokido\"");
        sendJson(exchange, 401, errorJson("invalid_client", description));
    }

    private static String successJson(TokenResult.Success ok) {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        boolean first = true;
        first = JsonWriter.appendRequiredStringField(sb, "access_token", ok.accessToken(), first);
        first = JsonWriter.appendRequiredStringField(sb, "token_type", ok.tokenType(), first);
        first = JsonWriter.appendNumberField(sb, "expires_in", ok.expiresIn().getSeconds(), first);
        first = JsonWriter.appendOptionalStringField(sb, "refresh_token", ok.refreshToken(), first);
        first = JsonWriter.appendOptionalStringField(sb, "id_token", ok.idToken(), first);
        if (!ok.scope().isEmpty()) {
            JsonWriter.appendRequiredStringField(sb, "scope", String.join(" ", ok.scope()), first);
        }
        sb.append('}');
        return sb.toString();
    }

    // ── /userinfo ───────────────────────────────────────────────────────────

    private void handleUserInfo(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())
                && !"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendStatus(exchange, 405);
            return;
        }
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        // RFC 6750 §2.1 requires case-insensitive scheme matching for "Bearer".
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            exchange.getResponseHeaders().add("WWW-Authenticate",
                    "Bearer error=\"invalid_token\"");
            sendJson(exchange, 401, errorJson("invalid_token", "missing bearer token"));
            return;
        }
        String token = authHeader.substring(7).trim();
        UserInfoRequest req;
        try {
            req = new UserInfoRequest(token);
        } catch (RuntimeException e) {
            exchange.getResponseHeaders().add("WWW-Authenticate",
                    "Bearer error=\"invalid_token\"");
            sendJson(exchange, 401, errorJson("invalid_token", e.getMessage()));
            return;
        }
        UserInfoResult result = engine.userInfo(req);
        if (result instanceof UserInfoResult.Success ok) {
            sendJson(exchange, 200, userInfoJson(ok));
        } else if (result instanceof UserInfoResult.Error err) {
            exchange.getResponseHeaders().add("WWW-Authenticate",
                    "Bearer error=\"" + err.code() + "\"");
            sendJson(exchange, 401, errorJson(err.code(), err.description()));
        } else {
            sendJson(exchange, 500, errorJson("server_error", "unexpected result"));
        }
    }

    private static String userInfoJson(UserInfoResult.Success ok) {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        boolean first = true;
        first = JsonWriter.appendRequiredStringField(sb, "sub", ok.subjectId(), first);
        for (UserClaim claim : ok.claims()) {
            // RC1: every claim emitted as a JSON string (matches IdTokenBuilder).
            first = JsonWriter.appendRequiredStringField(sb, claim.type(), claim.value(), first);
        }
        sb.append('}');
        return sb.toString();
    }

    // ── seed data ──────────────────────────────────────────────────────────

    private static Set<Client> seedClients() {
        Set<String> redirectUris = Set.of(
                // OIDF certification suite (production callbacks)
                "https://www.certification.openid.net/test/a/tokido/callback",
                "https://www.certification.openid.net/test/a/tokido/callback/implicit",
                // OIDF suite running locally (docker-compose). The suite
                // advertises HTTPS:8443 callbacks even when its actual server
                // is plain HTTP/8080 — the URL is a label captured from a
                // 302 Location header, not an HTTP target the SUT fetches.
                "https://localhost:8443/test/a/tokido/callback",
                "https://localhost:8443/test/a/tokido/callback/implicit",
                "https://localhost:8444/test-mtls/a/tokido/callback",
                "https://localhost:8444/test-mtls/a/tokido/callback/implicit",
                // Generic local-test callbacks for EngineAdapterTest
                "http://localhost:9999/cb",
                "https://app.example/cb");
        Set<String> allowedScopes = Set.of("openid", "profile", "email", "offline_access");
        Set<GrantType> allowedGrantTypes = Set.of(
                GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN);
        Set<ClientAuthenticationMethod> authMethods = Set.of(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                ClientAuthenticationMethod.NONE);

        Client client1 = new Client(
                CLIENT_ID,
                Set.of(new ClientSecret(CLIENT_SECRET, null, null)),
                redirectUris,
                Set.of(),
                allowedScopes,
                allowedGrantTypes,
                authMethods,
                /* requirePkce */ true,
                /* allowOfflineAccess */ true,
                ACCESS_TOKEN_LIFETIME,
                REFRESH_TOKEN_LIFETIME,
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                /* enabled */ true);
        Client client2 = new Client(
                CLIENT2_ID,
                Set.of(new ClientSecret(CLIENT2_SECRET, null, null)),
                redirectUris,
                Set.of(),
                allowedScopes,
                allowedGrantTypes,
                authMethods,
                true,
                true,
                ACCESS_TOKEN_LIFETIME,
                REFRESH_TOKEN_LIFETIME,
                RefreshTokenUsage.ONE_TIME,
                Map.of(),
                true);
        return Set.of(client1, client2);
    }

    private static Set<IdentityScope> seedScopes() {
        return Set.of(
                new IdentityScope("openid", null, Set.of("sub")),
                new IdentityScope("profile", null,
                        Set.of("name", "family_name", "given_name")),
                new IdentityScope("email", null,
                        Set.of("email", "email_verified")),
                new IdentityScope("offline_access", null, Set.of()));
    }

    private static MapUserStore seedUserStore() {
        User alice = new User(SEED_SUBJECT_ID, SEED_USERNAME, true, Map.of());
        Set<UserClaim> claims = Set.of(
                new UserClaim("sub", SEED_SUBJECT_ID),
                new UserClaim("name", "Alice Example"),
                new UserClaim("given_name", "Alice"),
                new UserClaim("family_name", "Example"),
                new UserClaim("email", "alice@example.com"),
                new UserClaim("email_verified", "true"));
        Map<String, Set<UserClaim>> claimsBySubject = new HashMap<>();
        claimsBySubject.put(SEED_SUBJECT_ID, claims);
        Map<String, String> passwords = new HashMap<>();
        passwords.put(SEED_USERNAME, SEED_PASSWORD);
        return new MapUserStore(Set.of(alice), passwords, Map.of(), claimsBySubject);
    }

    // ── HTTP helpers ────────────────────────────────────────────────────────

    private static void handle404(HttpExchange exchange) throws IOException {
        sendStatus(exchange, 404);
    }

    private static void handle501(HttpExchange exchange) throws IOException {
        sendStatus(exchange, 501);
    }

    private static void sendStatus(HttpExchange exchange, int status) throws IOException {
        debugReply(exchange, status);
        exchange.sendResponseHeaders(status, -1);
        exchange.close();
    }

    private static void sendText(HttpExchange exchange, int status, String body) throws IOException {
        debugReply(exchange, status);
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static void sendJson(HttpExchange exchange, int status, String body) throws IOException {
        debugReply(exchange, status);
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.getResponseHeaders().add("Cache-Control", "no-store");
        exchange.getResponseHeaders().add("Pragma", "no-cache");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    /**
     * Print one line to {@code System.err} with method, path, query, and
     * response status. Gated on {@link #DEBUG} so production runs stay quiet.
     * Headers are summarised by name only (not values) to avoid leaking
     * bearer tokens / Basic credentials into test logs.
     */
    private static void debugReply(HttpExchange exchange, int status) {
        if (!DEBUG) return;
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getRawQuery();
        String location = exchange.getResponseHeaders().getFirst("Location");
        StringBuilder line = new StringBuilder(128)
                .append("[engine-adapter] ").append(method).append(' ').append(path);
        if (query != null) line.append('?').append(query);
        line.append(" -> ").append(status);
        if (location != null) line.append("  Location=").append(location);
        System.err.println(line);
    }

    private static String errorJson(String code, String description) {
        StringBuilder sb = new StringBuilder(64);
        sb.append('{');
        boolean first = true;
        first = JsonWriter.appendRequiredStringField(sb, "error", code, first);
        JsonWriter.appendOptionalStringField(sb, "error_description", description, first);
        sb.append('}');
        return sb.toString();
    }

    // ── form / query parsing ────────────────────────────────────────────────

    /**
     * Parse {@code application/x-www-form-urlencoded} body. Last-wins for
     * duplicates, sufficient for RC1.
     */
    private static Map<String, String> parseFormBody(InputStream body) throws IOException {
        byte[] bytes = body.readAllBytes();
        if (bytes.length == 0) return Map.of();
        return parseQueryString(new String(bytes, StandardCharsets.UTF_8));
    }

    /**
     * Parse a URL-encoded query string ({@code a=1&b=2}) into a flat
     * {@code Map<String, String>}. Last-wins for duplicates, sufficient for
     * RC1. Empty / null input → empty map.
     */
    private static Map<String, String> parseQueryString(String query) {
        if (query == null || query.isEmpty()) return Map.of();
        Map<String, String> out = new LinkedHashMap<>();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            out.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                    URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return out;
    }

    /**
     * Parse a space-separated scope list ({@code "a b c"}); null/empty → empty
     * set. Tolerates duplicates ({@code "openid openid profile"}) — the OIDF
     * suite sends malformed lists in negative tests, and {@code Set.of(T...)}
     * would throw {@link IllegalArgumentException} on duplicates and surface
     * as a 500 instead of a 400 invalid_request.
     */
    private static Set<String> parseScopeList(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        String[] parts = raw.trim().split("\\s+");
        return new java.util.LinkedHashSet<>(java.util.Arrays.asList(parts));
    }

    /** Append URL-encoded params to {@code base}, picking {@code ?} or {@code &}. */
    private static String appendQuery(String base, Map<String, String> params) {
        if (params.isEmpty()) return base;
        StringBuilder sb = new StringBuilder(base);
        char sep = base.indexOf('?') < 0 ? '?' : '&';
        for (Map.Entry<String, String> e : params.entrySet()) {
            sb.append(sep);
            sb.append(java.net.URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8));
            sb.append('=');
            sb.append(java.net.URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
            sep = '&';
        }
        return sb.toString();
    }

    /** Random Base64url, no padding. Used for session ids (16 bytes → 22 chars). */
    private static String randomToken(int byteLength) {
        byte[] bytes = new byte[byteLength];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
