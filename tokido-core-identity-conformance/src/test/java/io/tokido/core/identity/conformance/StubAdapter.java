package io.tokido.core.identity.conformance;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.util.Set;

/**
 * In-process HTTP server that returns 501 Not Implemented for every OIDC endpoint.
 * Used at M0 so the OIDF conformance suite has a target before any engine code exists.
 * Replaced at M2 by an adapter wired to the real {@code IdentityEngine}.
 */
final class StubAdapter {

    private static final Set<String> OIDC_ENDPOINTS = Set.of(
            "/authorize",
            "/token",
            "/userinfo",
            "/.well-known/openid-configuration",
            "/jwks",
            "/introspect",
            "/revoke",
            "/end_session"
    );

    private final HttpServer server;

    private StubAdapter(HttpServer server) {
        this.server = server;
    }

    static StubAdapter start(int requestedPort) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(requestedPort), 0);
        server.createContext("/", exchange -> {
            int status = OIDC_ENDPOINTS.contains(exchange.getRequestURI().getPath()) ? 501 : 404;
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.start();
        return new StubAdapter(server);
    }

    int port() {
        return server.getAddress().getPort();
    }

    void stop() {
        server.stop(0);
    }
}
