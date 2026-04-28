package io.tokido.core.identity.conformance;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StubAdapterTest {

    private StubAdapter adapter;
    private HttpClient client;
    private int port;

    @BeforeEach
    void start() throws Exception {
        adapter = StubAdapter.start(0); // 0 == any free port
        port = adapter.port();
        client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
    }

    @AfterEach
    void stop() {
        adapter.stop();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/authorize",
            "/token",
            "/userinfo",
            "/.well-known/openid-configuration",
            "/jwks",
            "/introspect",
            "/revoke",
            "/end_session"
    })
    void endpointReturns501(String path) throws Exception {
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(501, response.statusCode(),
                "endpoint " + path + " should return 501 Not Implemented");
    }

    @Test
    void unknownPathReturns404() throws Exception {
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/no-such-thing"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(404, response.statusCode());
    }
}
