package io.tokido.core.identity.key;

import org.apiguardian.api.API;

/**
 * Lifecycle state of a signing key.
 *
 * <ul>
 *   <li>{@link #ACTIVE} — used for new signatures, present in JWKS.</li>
 *   <li>{@link #RETIRED} — no new signatures, still present in JWKS so
 *       previously-issued tokens validate during the rotation grace window
 *       (ADR-0007, M2).</li>
 * </ul>
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public enum KeyState {
    /** Eligible for new signatures and present in the JWKS endpoint. */
    ACTIVE,
    /** No new signatures, still in JWKS so prior tokens validate. */
    RETIRED
}
