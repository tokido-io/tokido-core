package io.tokido.core.identity.engine.discovery;

import io.tokido.core.identity.protocol.DiscoveryDocument;
import org.apiguardian.api.API;

import java.net.URI;
import java.util.Map;
import java.util.Set;

/**
 * Builds the OIDC discovery document from a fixed issuer + the capability
 * set the engine ships with at this milestone.
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2")
public final class DiscoveryHandler {

    private final URI issuer;
    private final URI authorize;
    private final URI token;
    private final URI userinfo;
    private final URI jwks;

    public DiscoveryHandler(URI issuer) {
        this.issuer = issuer;
        String base = issuer.toString().endsWith("/")
                ? issuer.toString()
                : issuer.toString() + "/";
        this.authorize = URI.create(base + "authorize");
        this.token = URI.create(base + "token");
        this.userinfo = URI.create(base + "userinfo");
        this.jwks = URI.create(base + "jwks");
    }

    public DiscoveryDocument build() {
        return new DiscoveryDocument(
                issuer,
                authorize,
                token,
                userinfo,
                jwks,
                null, null, null, // introspection, revocation, end_session — M2 final
                Set.of("code"),
                // RC1 advertises only what the token endpoint actually grants;
                // refresh_token + client_credentials restored when M2.RC2 / M2 lands them.
                Set.of("authorization_code"),
                Set.of("public"),
                Set.of("RS256"),
                Set.of("openid", "profile", "email"),
                Set.of("client_secret_basic", "client_secret_post", "none"),
                // RC1 omits acr/amr — IdTokenBuilder does not yet emit them.
                Set.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"),
                Map.of());
    }
}
