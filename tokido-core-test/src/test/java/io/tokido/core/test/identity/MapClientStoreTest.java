package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.AbstractClientStoreContract;
import io.tokido.core.identity.spi.Client;
import io.tokido.core.identity.spi.ClientStore;

import java.util.Set;

class MapClientStoreTest extends AbstractClientStoreContract {
    @Override
    protected ClientStore createStore(Set<Client> clients) {
        return new MapClientStore(clients);
    }
}
