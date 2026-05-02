package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.GrantType;
import io.tokido.core.identity.spi.PersistedGrant;
import io.tokido.core.identity.spi.TokenStore;
import org.apiguardian.api.API;

import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link TokenStore} with {@link Clock}-based expiration.
 * Concurrent-safe via {@link ConcurrentHashMap}; expired grants are filtered
 * from {@link #findByHandle} (and lazy-removed during the same call).
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class MapTokenStore implements TokenStore {

    private final ConcurrentHashMap<String, PersistedGrant> backing = new ConcurrentHashMap<>();
    private final Clock clock;

    public MapTokenStore(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override public void store(PersistedGrant grant) { backing.put(grant.handle(), grant); }

    @Override
    public PersistedGrant findByHandle(String handle) {
        PersistedGrant g = backing.get(handle);
        if (g == null) return null;
        if (!g.expiration().isAfter(clock.instant())) {
            backing.remove(handle, g);
            return null;
        }
        return g;
    }

    @Override public void remove(String handle) { backing.remove(handle); }

    @Override
    public void removeAll(String subjectId, String clientId) {
        backing.entrySet().removeIf(e ->
                e.getValue().subjectId().equals(subjectId)
                        && e.getValue().clientId().equals(clientId));
    }

    @Override
    public void removeAll(String subjectId, String clientId, GrantType type) {
        backing.entrySet().removeIf(e ->
                e.getValue().subjectId().equals(subjectId)
                        && e.getValue().clientId().equals(clientId)
                        && e.getValue().type() == type);
    }
}
