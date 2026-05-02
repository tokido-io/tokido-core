package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

/**
 * OAuth 2.0 / OIDC grant types supported by the engine. The wire-protocol
 * value (per RFC 6749 §1.3 and OIDC Core §3) is the lowercase, hyphenated
 * form of the enum name (e.g., {@code AUTHORIZATION_CODE} → {@code "authorization_code"}).
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public enum GrantType {
    /** OIDC Core §3.1, RFC 6749 §4.1 — the authorization code grant. */
    AUTHORIZATION_CODE,
    /** RFC 6749 §6 — the refresh token grant. */
    REFRESH_TOKEN,
    /** RFC 6749 §4.4 — the client credentials grant. */
    CLIENT_CREDENTIALS
}
