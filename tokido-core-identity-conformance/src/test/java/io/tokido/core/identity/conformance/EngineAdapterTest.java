package io.tokido.core.identity.conformance;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * HTTP-level integration tests for {@link EngineAdapter}. Drives the
 * in-process server with {@link HttpClient} and asserts on status codes,
 * headers, and JSON body shapes. Each test runs the full engine, but at
 * loopback only — the OIDF docker suite is exercised by {@code OidcConformanceIT},
 * not here.
 *
 * <p>The adapter is started with {@code "localhost"} as the issuer host so
 * the test JVM can reach itself without going through Docker's host gateway.
 */
class EngineAdapterTest {

    private EngineAdapter adapter;
    private HttpClient client;
    private int port;

    @BeforeEach
    void start() throws Exception {
        adapter = EngineAdapter.start(0, "localhost");
        port = adapter.port();
        client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                // Don't follow redirects automatically — many tests assert on
                // the 302 Location header.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @AfterEach
    void stop() {
        adapter.stop();
    }

    // ── /.well-known/openid-configuration ───────────────────────────────────

    @Test
    void discoveryReturnsExpectedFields() throws Exception {
        HttpResponse<String> response = get("/.well-known/openid-configuration");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type"))
                .hasValueSatisfying(ct -> assertThat(ct).startsWith("application/json"));
        String body = response.body();
        assertThat(body)
                .contains("\"issuer\":\"http://localhost:" + port + "/\"")
                .contains("\"authorization_endpoint\":\"http://localhost:" + port + "/authorize\"")
                .contains("\"token_endpoint\":\"http://localhost:" + port + "/token\"")
                .contains("\"userinfo_endpoint\":\"http://localhost:" + port + "/userinfo\"")
                .contains("\"jwks_uri\":\"http://localhost:" + port + "/jwks\"")
                .contains("\"code\"")
                .contains("\"RS256\"")
                .contains("\"S256\"");
    }

    // ── /jwks ───────────────────────────────────────────────────────────────

    @Test
    void jwksReturnsAtLeastOneRsaKey() throws Exception {
        HttpResponse<String> response = get("/jwks");
        assertThat(response.statusCode()).isEqualTo(200);
        String body = response.body();
        assertThat(body)
                .contains("\"keys\"")
                .contains("\"kty\":\"RSA\"")
                .contains("\"use\":\"sig\"")
                .contains("\"alg\":\"RS256\"")
                .contains("\"kid\"")
                .contains("\"n\"")
                .contains("\"e\":\"AQAB\"");
    }

    // ── /authorize ──────────────────────────────────────────────────────────

    @Test
    void authorizeWithoutClientIdReturns400() throws Exception {
        // No client_id and no redirect_uri → engine returns invalid_client and
        // no redirect target is available, so the adapter renders 400 instead
        // of redirecting.
        HttpResponse<String> response = get("/authorize?response_type=code");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("invalid_client");
    }

    @Test
    void authorizeHappyPathRedirectsWithCodeAndState() throws Exception {
        String verifier = "dBjftJeZ4CVPmB92K27uhbUJU1p1r-wW1gFWFOEjXk_1234567890ab";
        String challenge = pkceS256(verifier);
        String authorizeUrl = "/authorize"
                + "?response_type=code"
                + "&client_id=" + EngineAdapter.CLIENT_ID
                + "&redirect_uri=" + urlEncode("http://localhost:9999/cb")
                + "&scope=" + urlEncode("openid profile email")
                + "&state=xyz-state"
                + "&nonce=n-1"
                + "&code_challenge=" + challenge
                + "&code_challenge_method=S256";

        HttpResponse<String> response = get(authorizeUrl);

        assertThat(response.statusCode()).isEqualTo(302);
        String location = response.headers().firstValue("Location").orElseThrow();
        assertThat(location)
                .startsWith("http://localhost:9999/cb?")
                .contains("code=")
                .contains("state=xyz-state");
    }

    @Test
    void tokenCodeGrantHappyPathReturnsTokens() throws Exception {
        TokenExchange exchange = runFullCodeFlow(
                "openid profile email",
                "http://localhost:9999/cb",
                EngineAdapter.CLIENT_ID, EngineAdapter.CLIENT_SECRET);

        assertThat(exchange.tokenResponse.statusCode()).isEqualTo(200);
        String body = exchange.tokenResponse.body();
        assertThat(body)
                .contains("\"access_token\"")
                .contains("\"id_token\"")
                .contains("\"refresh_token\"")
                .contains("\"token_type\":\"Bearer\"")
                .contains("\"expires_in\":");
    }

    @Test
    void userInfoWithBearerFromCodeFlowReturnsSub() throws Exception {
        TokenExchange exchange = runFullCodeFlow(
                "openid profile email",
                "http://localhost:9999/cb",
                EngineAdapter.CLIENT_ID, EngineAdapter.CLIENT_SECRET);
        String accessToken = extractStringField(exchange.tokenResponse.body(), "access_token");

        HttpResponse<String> userinfo = client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/userinfo"))
                        .header("Authorization", "Bearer " + accessToken)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(userinfo.statusCode()).isEqualTo(200);
        assertThat(userinfo.body()).contains("\"sub\":\"" + EngineAdapter.SEED_SUBJECT_ID + "\"");
    }

    @Test
    void userInfoWithoutBearerReturns401() throws Exception {
        HttpResponse<String> response = get("/userinfo");
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("WWW-Authenticate"))
                .hasValueSatisfying(h -> assertThat(h).contains("invalid_token"));
    }

    @Test
    void userInfoWithInvalidBearerReturns401() throws Exception {
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/userinfo"))
                        .header("Authorization", "Bearer not-a-real-token")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).contains("invalid_token");
    }

    @Test
    void tokenRequestWithBadVerifierReturnsInvalidGrant() throws Exception {
        TokenExchange exchange = runFullCodeFlow(
                "openid", "http://localhost:9999/cb",
                EngineAdapter.CLIENT_ID, EngineAdapter.CLIENT_SECRET,
                /* tamperVerifier */ true);
        assertThat(exchange.tokenResponse.statusCode()).isEqualTo(400);
        assertThat(exchange.tokenResponse.body()).contains("invalid_grant");
    }

    @Test
    void tokenCodeReuseTriggersTheftDetection() throws Exception {
        TokenExchange first = runFullCodeFlow(
                "openid", "http://localhost:9999/cb",
                EngineAdapter.CLIENT_ID, EngineAdapter.CLIENT_SECRET);
        assertThat(first.tokenResponse.statusCode()).isEqualTo(200);

        // Replay the same code with the same verifier → engine flags reuse
        // and wipes grants for (subject, client). Adapter renders 400.
        HttpResponse<String> replay = postForm("/token", first.tokenForm);
        assertThat(replay.statusCode()).isEqualTo(400);
        assertThat(replay.body()).contains("invalid_grant");
    }

    @Test
    void authorizeWithDuplicateScopesDoesNotCrash() throws Exception {
        // RFC 6749 §3.3 leaves duplicate scopes underspecified, but the OIDF
        // suite occasionally sends "openid openid profile" in negative tests.
        // The adapter must not 500 — Set.of(T...) would throw on duplicates,
        // so parseScopeList uses a duplicate-tolerant LinkedHashSet.
        String verifier = "dBjftJeZ4CVPmB92K27uhbUJU1p1r-wW1gFWFOEjXk_dupescp012";
        String challenge = pkceS256(verifier);
        String authorizeUrl = "/authorize"
                + "?response_type=code"
                + "&client_id=" + EngineAdapter.CLIENT_ID
                + "&redirect_uri=" + urlEncode("http://localhost:9999/cb")
                + "&scope=" + urlEncode("openid openid profile")
                + "&state=dup-scope-state"
                + "&nonce=n-1"
                + "&code_challenge=" + challenge
                + "&code_challenge_method=S256";

        HttpResponse<String> response = get(authorizeUrl);

        // Either a 302 redirect (engine accepted the de-duplicated set) or a
        // 302/400 with invalid_scope is acceptable — what we forbid is a 500.
        assertThat(response.statusCode()).isNotEqualTo(500);
    }

    @Test
    void userInfoAcceptsLowercaseBearerScheme() throws Exception {
        // RFC 6750 §2.1 requires case-insensitive scheme matching for "Bearer".
        TokenExchange exchange = runFullCodeFlow(
                "openid profile email",
                "http://localhost:9999/cb",
                EngineAdapter.CLIENT_ID, EngineAdapter.CLIENT_SECRET);
        String accessToken = extractStringField(exchange.tokenResponse.body(), "access_token");

        HttpResponse<String> userinfo = client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/userinfo"))
                        .header("Authorization", "bearer " + accessToken)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(userinfo.statusCode()).isEqualTo(200);
        assertThat(userinfo.body()).contains("\"sub\":\"" + EngineAdapter.SEED_SUBJECT_ID + "\"");
    }

    @Test
    void tokenWithBadClientSecretReturns401WithWwwAuthenticate() throws Exception {
        // RFC 6749 §5.2: invalid_client must return 401 (not 400) when the
        // client attempted to authenticate, and SHOULD include WWW-Authenticate.
        TokenExchange exchange = runFullCodeFlow(
                "openid", "http://localhost:9999/cb",
                EngineAdapter.CLIENT_ID, "wrong-secret");
        assertThat(exchange.tokenResponse.statusCode()).isEqualTo(401);
        assertThat(exchange.tokenResponse.body()).contains("invalid_client");
        assertThat(exchange.tokenResponse.headers().firstValue("WWW-Authenticate"))
                .hasValueSatisfying(h -> assertThat(h).startsWith("Basic"));
    }

    @Test
    void unknownPathReturns404() throws Exception {
        HttpResponse<String> response = get("/no-such-thing");
        assertThat(response.statusCode()).isEqualTo(404);
    }

    @Test
    void deferredEndpointsReturn501() throws Exception {
        // /introspect, /revoke, /end_session aren't wired to the engine yet;
        // keep the legacy 501 response so any suite probe gets a clear answer.
        assertThat(get("/introspect").statusCode()).isEqualTo(501);
        assertThat(get("/revoke").statusCode()).isEqualTo(501);
        assertThat(get("/end_session").statusCode()).isEqualTo(501);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    /** Capture the per-flow data we need to drive token-endpoint assertions. */
    private record TokenExchange(HttpResponse<String> tokenResponse, String tokenForm) { }

    private TokenExchange runFullCodeFlow(String scope, String redirectUri,
                                          String clientId, String clientSecret) throws Exception {
        return runFullCodeFlow(scope, redirectUri, clientId, clientSecret, false);
    }

    /**
     * Run the full authorize → token round-trip and return the token-endpoint
     * response plus the form body (so callers can replay it).
     */
    private TokenExchange runFullCodeFlow(String scope, String redirectUri,
                                          String clientId, String clientSecret,
                                          boolean tamperVerifier) throws Exception {
        String verifier = "dBjftJeZ4CVPmB92K27uhbUJU1p1r-wW1gFWFOEjXk_abcdef0123";
        String challenge = pkceS256(verifier);
        String authorizeUrl = "/authorize"
                + "?response_type=code"
                + "&client_id=" + urlEncode(clientId)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&scope=" + urlEncode(scope)
                + "&state=xyz"
                + "&nonce=n-1"
                + "&code_challenge=" + challenge
                + "&code_challenge_method=S256";
        HttpResponse<String> authorize = get(authorizeUrl);
        if (authorize.statusCode() != 302) {
            throw new IllegalStateException(
                    "expected 302 from /authorize; got " + authorize.statusCode()
                            + " body=" + authorize.body());
        }
        String location = authorize.headers().firstValue("Location").orElseThrow();
        String code = extractQueryParam(location, "code");

        String submittedVerifier = tamperVerifier
                ? "this-is-not-the-original-verifier-and-should-fail-pkce-check"
                : verifier;
        String form = "grant_type=authorization_code"
                + "&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&code_verifier=" + urlEncode(submittedVerifier)
                + "&client_id=" + urlEncode(clientId)
                + "&client_secret=" + urlEncode(clientSecret);
        HttpResponse<String> tokenResponse = postForm("/token", form);
        return new TokenExchange(tokenResponse, form);
    }

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postForm(String path, String form) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** PKCE S256 challenge derivation per RFC 7636. */
    private static String pkceS256(String verifier) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    /**
     * Extract the value of {@code name} from a URL's query string. Naive
     * (no escaping concerns), sufficient for the well-formed redirects the
     * adapter emits.
     */
    private static String extractQueryParam(String url, String name) {
        int q = url.indexOf('?');
        if (q < 0) return null;
        for (String pair : url.substring(q + 1).split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            if (pair.substring(0, eq).equals(name)) {
                return java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /**
     * Extract the value of a JSON string field. Reuses {@link JsonScrape}'s
     * brittle-but-good-enough scraper rather than pulling in a JSON library
     * — same reasoning as in {@code OidcConformanceIT}.
     */
    private static String extractStringField(String json, String field) {
        return JsonScrape.extractStringField(json, field);
    }
}
