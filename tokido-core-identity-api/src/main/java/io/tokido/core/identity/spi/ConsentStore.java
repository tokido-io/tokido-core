package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

/**
 * Stores user consents per (subject, client) tuple. Looked up on every
 * authorize call to skip the consent screen for previously-consented scopes.
 *
 * <p>Thread-safety: implementations must be safe for concurrent reads;
 * {@link #store} and {@link #remove} must be atomic per-key.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface ConsentStore {

    /**
     * Look up an existing consent.
     *
     * @param subjectId subject
     * @param clientId  client
     * @return the consent, or {@code null} if no prior consent exists
     */
    Consent find(String subjectId, String clientId);

    /**
     * Persist a consent. Replaces any prior consent for the same (subject, client).
     *
     * @param consent the consent to store
     */
    void store(Consent consent);

    /**
     * Remove a consent. No-op if no consent exists.
     *
     * @param subjectId subject
     * @param clientId  client
     */
    void remove(String subjectId, String clientId);
}
