package io.tokido.core.identity.conformance;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test driving the OIDF conformance suite against the {@link EngineAdapter}.
 *
 * <p>Boot order:
 * <ol>
 *   <li>{@link EngineAdapter} on a free port (the SUT).</li>
 *   <li>OIDF conformance suite + MongoDB via {@code docker compose up}.</li>
 *   <li>Submit a test plan via the suite REST API targeting the SUT's URL.</li>
 *   <li>For each module in the plan, create a test instance via the runner API.</li>
 *   <li>Poll each test instance until FINISHED or INTERRUPTED.</li>
 *   <li>Assert pass-count >= floor for the current milestone (env var
 *       {@code CONFORMANCE_FLOOR}; default 0; see {@link #milestoneFloor()}).</li>
 * </ol>
 *
 * <p>The OIDF conformance suite REST API (confirmed by live probing against
 * release-v5.1.42 at registry.gitlab.com/openid/conformance-suite):
 * <ul>
 *   <li>{@code POST /api/plan?planName=&lt;name&gt;&variant=&lt;json&gt;} — create plan;
 *       body is the JSON config object; returns 201 with
 *       {@code {"id":"...","modules":[{"testModule":"...","instances":[]},...],...}}</li>
 *   <li>{@code GET /api/plan/{id}} — retrieve plan with modules list</li>
 *   <li>{@code POST /api/runner?test=&lt;module&gt;&plan=&lt;planId&gt;} — instantiate one
 *       test module; returns 201 with {@code {"id":"...","name":"...","url":"...",...}}</li>
 *   <li>{@code GET /api/info/{testId}} — poll test; returns
 *       {@code {"status":"FINISHED|INTERRUPTED|...","result":"PASSED|FAILED|...,...}}</li>
 * </ul>
 *
 * <p>The prebuilt container image runs the Java application on plain HTTP/8080
 * (no nginx TLS proxy bundled).  The suite's {@code RejectPlainHttpTrafficFilter}
 * demands an HTTPS context; we satisfy it by sending
 * {@code X-Forwarded-Proto: https} on every request — this is the documented way
 * to use the suite behind a reverse proxy, and {@code devmode=true} configures
 * Spring Security to honour it.
 *
 * <p>{@code devmode=true} (in docker-compose {@code JAVA_EXTRA_ARGS}) also injects a
 * dummy "developer" admin user so no real OAuth credentials are required.  The
 * Google/GitLab client-ID env vars must still be non-empty (set to {@code "dummy"})
 * to pass Spring Boot's property validation at startup.
 *
 * <p>The {@code conformance-results.json} file written to {@code target/} captures the
 * run summary so the {@code conformance-badge} workflow can update the README badge.
 */
class OidcConformanceIT {

    // The OIDF suite's Spring Boot context takes ~3-6 min on a fast laptop
    // (MongoDB index creation + extensive class scanning).  CI machines are often
    // slower.  10 min provides a generous margin.
    private static final Duration BOOT_TIMEOUT = Duration.ofMinutes(10);
    // M2.RC1: per-module timeout is intentionally short. In unattended mode
    // (no Selenium / Playwright driver) OIDF tests progress through their
    // setup phase, then stall waiting for a "browser" to drive the redirect
    // chain. The suite's own per-test timeout is 5 min; setting ours to 30s
    // means the IT terminates within ~17 minutes worst-case (35 × 30s) rather
    // than 175 minutes. Each module that *does* run will finish in well
    // under 30s on real engine flows. Restore to 5+ minutes once the suite
    // has a browser-driver attached (M2.RC2).
    private static final Duration MODULE_TIMEOUT = Duration.ofSeconds(30);
    private static final Path COMPOSE_FILE =
            Path.of("src/test/resources/docker-compose.yml");
    private static final Path RESULTS_FILE = Path.of("target/conformance-results.json");

    // The prebuilt OIDF container image runs the Java application on plain HTTP/8080
    // (the dev docker-compose adds an nginx TLS proxy separately; we skip that).
    private static final URI SUITE_BASE = URI.create("http://localhost:8080");

    /**
     * Variants required by {@code oidcc-basic-certification-test-plan}.
     * <ul>
     *   <li>{@code server_metadata=discovery} — use the OIDC discovery document
     *       ({@code /.well-known/openid-configuration}) instead of static endpoint config.</li>
     *   <li>{@code client_registration=static_client} — pre-registered clients; dynamic
     *       registration is impossible when the SUT returns 501 for everything.</li>
     * </ul>
     */
    private static final String PLAN_VARIANT =
            "{\"server_metadata\":\"discovery\",\"client_registration\":\"static_client\"}";

    /**
     * Plan name for the basic OIDC certification test plan.
     * Confirmed present in GET /api/plan/available on release-v5.1.42.
     */
    private static final String PLAN_NAME = "oidcc-basic-certification-test-plan";

    private static EngineAdapter sut;
    private static HttpClient http;

    @BeforeAll
    static void bootSutAndSuite() throws Exception {
        sut = EngineAdapter.start(0);

        // The OIDF container serves plain HTTP on port 8080.
        // Response times over the Colima/Lima SSH tunnel can be 10+ seconds per
        // request; set a generous timeout.
        http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();

        runOrFail("docker", "compose", "-f", COMPOSE_FILE.toString(), "up", "-d");
        waitUntilSuiteReady();
    }

    @AfterAll
    static void teardown() {
        try {
            if (sut != null) sut.stop();
        } catch (Exception e) {
            System.err.println("Failed to stop SUT: " + e.getMessage());
        }
        try {
            runOrFail("docker", "compose", "-f", COMPOSE_FILE.toString(), "down", "-v");
        } catch (Exception e) {
            System.err.println("Failed to docker compose down: " + e.getMessage());
        }
    }

    @Test
    void basicCertificationTestPlanPassRateMeetsMilestoneFloor() throws Exception {
        long passed = 0;
        long total = 0;
        try {
            // ── Step 1: create the test plan ────────────────────────────────────────
            //
            // POST /api/plan?planName=<name>&variant=<json>
            // Body: JSON configuration.  The suite's container reaches the SUT via
            // "host.docker.internal" (resolves to the Docker host IP).  The extra_hosts
            // entry in docker-compose maps it on Linux/CI; on Mac Docker Desktop / Colima
            // it resolves automatically.
            //
            // The plan requires two variants (see PLAN_VARIANT) and the
            // pre-seeded EngineAdapter clients (matching the IDs/secrets the
            // adapter wires in seedClients()).
            // alias = "tokido" pins the suite-generated callback URL to
            // {base}/test/a/tokido/callback, which the EngineAdapter's seeded
            // clients pre-register. Without this, the suite generates a random
            // alias and our exact-match redirect_uri check rejects the
            // resulting callback URL — every test then hangs at /authorize.
            String config = """
                    {
                      "alias": "tokido",
                      "description": "M2.RC1 conformance run with EngineAdapter",
                      "server": {
                        "discoveryUrl": "http://host.docker.internal:%d/.well-known/openid-configuration"
                      },
                      "client": {
                        "client_id": "tokido_m0_client",
                        "client_secret": "tokido_m0_secret"
                      },
                      "client2": {
                        "client_id": "tokido_m0_client2",
                        "client_secret": "tokido_m0_secret2"
                      }
                    }
                    """.formatted(sut.port());

            String planId = createPlan(config);
            assertFalse(planId.isBlank(), "plan creation should return a non-empty ID");

            // ── Step 2: instantiate every module in the plan ────────────────────────
            //
            // GET /api/plan/{id} → {modules:[{testModule,...},...]}.
            // POST /api/runner?test=<module>&plan=<planId> → {id,...}.
            List<String> moduleNames = fetchPlanModules(planId);
            List<String> testIds = new ArrayList<>();
            for (String moduleName : moduleNames) {
                String testId = createTestInstance(planId, moduleName);
                testIds.add(testId);
            }

            // ── Step 3: poll until each module reaches a terminal state ──────────────
            //
            // GET /api/info/{testId} → {status, result, ...}
            // Terminal status values: FINISHED, INTERRUPTED
            // result values: PASSED, FAILED, WARNING, REVIEW, SKIPPED, UNKNOWN
            total = testIds.size();
            boolean firstNonPassLogged = false;
            for (String testId : testIds) {
                String result;
                try {
                    result = pollUntilFinished(testId, MODULE_TIMEOUT);
                } catch (IllegalStateException timeout) {
                    // Tests that stall in WAITING (the unattended-mode case
                    // until a Selenium driver lands at M2.RC2) hit our poll
                    // deadline. Treat as non-pass and keep iterating so the
                    // remaining tests still get tabulated.
                    result = "TIMEOUT";
                    System.err.println("[oidf] " + testId + " " + timeout.getMessage());
                }
                if ("PASSED".equals(result)) {
                    passed++;
                } else if (!firstNonPassLogged) {
                    // Dump the suite's structured log for the first non-pass
                    // (FAILED, INTERRUPTED, TIMEOUT) so we have ground-truth
                    // on why our SUT is failing OIDF validation. Subsequent
                    // non-passes usually share the same root cause.
                    dumpTestLog(testId);
                    firstNonPassLogged = true;
                }
            }
        } finally {
            // ── Step 4: write summary ────────────────────────────────────────────────
            // Always write partial results so the conformance-badge workflow can update
            // the README badge even when the run fails or times out mid-way.
            writeResultsFile(passed, total);
        }

        long floor = milestoneFloor();
        assertTrue(passed >= floor,
                "OIDF pass-count " + passed + "/" + total
                        + " is below milestone floor " + floor);
    }

    /**
     * Print the suite's structured log for {@code testId} to {@code System.err}.
     * Best-effort: any failure here is logged but does not propagate, since
     * the diagnostic should never mask the underlying test failure.
     */
    private static void dumpTestLog(String testId) {
        try {
            HttpResponse<String> response = send(
                    HttpRequest.newBuilder(SUITE_BASE.resolve("/api/log/" + testId))
                            .GET());
            System.err.println("[oidf-log] " + testId + " (status=" + response.statusCode() + "):");
            System.err.println(response.body());
        } catch (Exception e) {
            System.err.println("[oidf-log] dump failed for " + testId + ": " + e.getMessage());
        }
    }

    private static void writeResultsFile(long passed, long total) {
        try {
            Path parent = RESULTS_FILE.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(RESULTS_FILE, "{\"passed\":" + passed + ",\"total\":" + total + "}");
        } catch (Exception e) {
            // Don't mask the test failure with a results-write failure.
            System.err.println("Failed to write conformance-results.json: " + e.getMessage());
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────────

    /**
     * Per-milestone OIDF basic-cert pass-count floor: M0/M1=0 (no engine work
     * landed); M2.RC1=0 (Selenium driver lands at M2.RC2); M2≥18 (target);
     * M3≥27; M4≥32; M5=35. CI overrides via {@code CONFORMANCE_FLOOR} env var.
     */
    private static long milestoneFloor() {
        String fromEnv = System.getenv("CONFORMANCE_FLOOR");
        return fromEnv != null ? Long.parseLong(fromEnv) : 0L;
    }

    /**
     * Sends an HTTP request with the {@code X-Forwarded-Proto: https} header.
     *
     * <p>The OIDF suite's {@code RejectPlainHttpTrafficFilter} rejects plain HTTP
     * requests with a 500 unless this header is present.  It is the documented way
     * to use the suite behind a reverse proxy.
     */
    private static HttpResponse<String> send(HttpRequest.Builder builder) throws Exception {
        return http.send(
                builder.header("X-Forwarded-Proto", "https").build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Creates a test plan.
     *
     * <p>Confirmed API (live-probed): {@code POST /api/plan?planName=&lt;name&gt;&variant=&lt;json&gt;}
     * with config JSON as the request body.
     * Returns 201 {@code {"id":"...","planName":"...","modules":[...],...}}.
     */
    private static String createPlan(String configJson) throws Exception {
        String url = SUITE_BASE
                + "/api/plan?planName="
                + URLEncoder.encode(PLAN_NAME, StandardCharsets.UTF_8)
                + "&variant="
                + URLEncoder.encode(PLAN_VARIANT, StandardCharsets.UTF_8);
        HttpResponse<String> response = send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(configJson)));
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException(
                    "plan creation failed: " + response.statusCode()
                            + "\n" + response.body());
        }
        return JsonScrape.extractStringField(response.body(), "id");
    }

    /**
     * Retrieves the list of test module names from a plan.
     *
     * <p>Confirmed API: {@code GET /api/plan/{id}} returns
     * {@code {"id":"...","modules":[{"testModule":"...","instances":[]},...],...}}.
     */
    private static List<String> fetchPlanModules(String planId) throws Exception {
        HttpResponse<String> response = send(
                HttpRequest.newBuilder(SUITE_BASE.resolve("/api/plan/" + planId))
                        .GET());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException(
                    "GET /api/plan/" + planId + " failed: " + response.statusCode()
                            + "\n" + response.body());
        }
        return JsonScrape.extractModuleNames(response.body());
    }

    /**
     * Instantiates one test module inside a plan.
     *
     * <p>Confirmed API: {@code POST /api/runner?test=&lt;module&gt;&plan=&lt;planId&gt;}
     * returns 201 {@code {"id":"...","name":"...","url":"...",...}}.
     *
     * <p>OIDF tests progress through their setup phase (discovery, JWKS
     * fetch, request build) automatically once created — no external "start
     * signal" is needed. After setup the test is "redirecting" the simulated
     * browser to the SUT's authorize endpoint. Driving the redirect chain
     * onward requires a real browser-driver (Selenium / Playwright); in
     * unattended mode tests stall here and the suite eventually marks them
     * INTERRUPTED. Adding a Selenium runner is M2.RC2 work.
     */
    private static String createTestInstance(String planId, String moduleName) throws Exception {
        String url = SUITE_BASE
                + "/api/runner?test="
                + URLEncoder.encode(moduleName, StandardCharsets.UTF_8)
                + "&plan="
                + URLEncoder.encode(planId, StandardCharsets.UTF_8);
        HttpResponse<String> response = send(
                HttpRequest.newBuilder(URI.create(url))
                        .POST(HttpRequest.BodyPublishers.noBody()));
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException(
                    "test instance creation failed for module " + moduleName
                            + ": " + response.statusCode() + "\n" + response.body());
        }
        return JsonScrape.extractStringField(response.body(), "id");
    }

    /**
     * Polls {@code GET /api/info/{testId}} until the test reaches a terminal state
     * ({@code FINISHED} or {@code INTERRUPTED}), then returns the {@code result} value.
     *
     * <p>Each status transition is logged to {@code System.err}; on timeout the
     * last-seen status + result are included in the failure message to make
     * stuck-test debugging tractable without re-running the suite.
     */
    private static String pollUntilFinished(String testId, Duration timeout) throws Exception {
        Instant deadline = Instant.now().plus(timeout);
        String lastStatus = "";
        String lastResult = "";
        while (Instant.now().isBefore(deadline)) {
            try {
                HttpResponse<String> response = send(
                        HttpRequest.newBuilder(SUITE_BASE.resolve("/api/info/" + testId))
                                .GET());
                String body = response.body();
                String status = JsonScrape.extractStringFieldOrEmpty(body, "status");
                String result = JsonScrape.extractStringFieldOrEmpty(body, "result");
                if (!status.equals(lastStatus) || !result.equals(lastResult)) {
                    System.err.println("[oidf] " + testId + " status=" + status + " result=" + result);
                    lastStatus = status;
                    lastResult = result;
                }
                if ("FINISHED".equals(status) || "INTERRUPTED".equals(status)) {
                    return result;
                }
            } catch (Exception e) {
                // Transient error — keep polling, but log so persistent failures surface in CI logs.
                System.err.println("poll attempt failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            Thread.sleep(3_000);
        }
        throw new IllegalStateException(
                "test " + testId + " did not finish within " + timeout
                        + " (last status=" + lastStatus + " result=" + lastResult + ")");
    }

    /**
     * Waits until the suite REST API is reachable and accepting requests.
     *
     * <p>Uses {@code GET /api/plan/available} because {@code GET /api/info} is
     * permanently disabled in v5.1.42 for performance reasons.  A 200 response
     * means the Spring context is fully up and the API is ready.
     */
    private static void waitUntilSuiteReady() throws Exception {
        Instant deadline = Instant.now().plus(BOOT_TIMEOUT);
        while (Instant.now().isBefore(deadline)) {
            try {
                HttpResponse<String> response = send(
                        HttpRequest.newBuilder(SUITE_BASE.resolve("/api/plan/available"))
                                .GET());
                if (response.statusCode() == 200) {
                    return;
                }
            } catch (Exception ignored) {
                // Suite not ready yet.
            }
            Thread.sleep(5_000);
        }
        throw new IllegalStateException(
                "OIDF suite did not become ready within " + BOOT_TIMEOUT);
    }

    private static void runOrFail(String... cmd) throws Exception {
        Process process = new ProcessBuilder(cmd).inheritIO().start();
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IllegalStateException(
                    "command failed (exit " + exit + "): " + String.join(" ", cmd));
        }
    }

}
