package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

/**
 * Source of OAuth/OIDC client registrations. Read-only at the engine
 * surface; implementations may persist clients however they wish.
 *
 * <p>Thread-safety: implementations must be safe for concurrent reads.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface ClientStore {

    /**
     * Look up a client by ID.
     *
     * @param clientId the client identifier
     * @return the client, or {@code null} if no client is registered with this ID.
     *         The {@code null} contract matches the existing tokido-core
     *         {@code SecretStore.load} convention; consumers are responsible
     *         for {@code null} checking.
     */
    Client findById(String clientId);

    /**
     * Quick existence probe; equivalent to {@code findById(clientId) != null}
     * but may be faster for stores that index by id.
     *
     * @param clientId the client identifier
     * @return true if a client is registered with this ID
     */
    boolean exists(String clientId);
}
