package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientStore;
import org.apiguardian.api.API;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * In-memory {@link ClientStore} backed by an immutable {@code Map<clientId, Client>}.
 * Constructor takes a seed set of clients.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class MapClientStore implements ClientStore {

    private final Map<String, Client> byId;

    public MapClientStore(Set<Client> clients) {
        Objects.requireNonNull(clients, "clients");
        Map<String, Client> mutable = new HashMap<>();
        for (Client c : clients) mutable.put(c.clientId(), c);
        this.byId = Map.copyOf(mutable);
    }

    @Override public Client findById(String clientId) { return byId.get(clientId); }
    @Override public boolean exists(String clientId) { return byId.containsKey(clientId); }
}
