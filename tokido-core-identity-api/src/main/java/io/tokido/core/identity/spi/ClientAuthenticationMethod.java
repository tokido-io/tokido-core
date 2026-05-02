package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

/**
 * Supported client authentication methods at the token endpoint, per
 * OIDC Core §9 and RFC 6749 §2.3. The wire-protocol value is the
 * lowercase form of the enum name (e.g., {@code CLIENT_SECRET_BASIC}
 * → {@code "client_secret_basic"}).
 *
 * <p>Note: mTLS ({@code tls_client_auth}) and private-key JWT
 * ({@code private_key_jwt}) are deferred to 0.2 per project-A doc §11.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public enum ClientAuthenticationMethod {
    /** RFC 6749 §2.3.1 — HTTP Basic auth with client_id/client_secret. */
    CLIENT_SECRET_BASIC,
    /** RFC 6749 §2.3.1 — client_id/client_secret in the request body. */
    CLIENT_SECRET_POST,
    /** OIDC Core §9 — public client; no client authentication. */
    NONE
}
