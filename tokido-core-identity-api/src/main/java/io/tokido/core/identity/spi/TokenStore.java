package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

/**
 * Persisted-grant store. Backs authorization codes, refresh tokens, reference
 * tokens, and consent grants. Named {@code TokenStore} per ADR-0001 (Duende
 * calls it {@code PersistedGrantStore} but {@code TokenStore} is more
 * discoverable to Java developers).
 *
 * <p>Thread-safety: {@link #findByHandle} must be safe for concurrent reads.
 * {@link #store}, {@link #remove}, and the bulk-remove methods must be
 * atomic per-handle.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface TokenStore {

    /**
     * Persist a grant. If a grant with the same handle exists, behavior is
     * implementation-defined (typically replace).
     *
     * @param grant the grant to persist
     */
    void store(PersistedGrant grant);

    /**
     * Look up by handle.
     *
     * @param handle the grant's opaque server-side identifier
     * @return the grant, or {@code null} for unknown handles AND for expired
     *         grants (implementations are responsible for the expiration check)
     */
    PersistedGrant findByHandle(String handle);

    /**
     * Remove a single grant by handle. No-op if the handle is unknown.
     *
     * @param handle the grant's identifier
     */
    void remove(String handle);

    /**
     * Remove every grant for the given (subjectId, clientId).
     *
     * @param subjectId subject
     * @param clientId  client
     */
    void removeAll(String subjectId, String clientId);

    /**
     * Remove every grant for the given (subjectId, clientId) of the given type.
     *
     * @param subjectId subject
     * @param clientId  client
     * @param type      grant type filter
     */
    void removeAll(String subjectId, String clientId, GrantType type);
}
