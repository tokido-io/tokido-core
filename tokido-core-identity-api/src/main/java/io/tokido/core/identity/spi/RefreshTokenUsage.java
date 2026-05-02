package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

/**
 * Refresh-token rotation policy per client. {@code ONE_TIME} (default)
 * means each refresh consumes the prior refresh token and issues a new
 * one; {@code REUSE} permits the same refresh token to be used until
 * its lifetime expires. ADR-0008 (M2) covers the rotation mechanics
 * and theft-detection rules.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public enum RefreshTokenUsage {
    /** Each refresh consumes the prior refresh token; a new one is issued. */
    ONE_TIME,
    /** The same refresh token may be used until expiration. */
    REUSE
}
