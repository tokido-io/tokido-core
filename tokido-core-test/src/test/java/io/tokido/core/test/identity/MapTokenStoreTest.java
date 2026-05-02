package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.AbstractTokenStoreContract;
import io.tokido.core.identity.spi.TokenStore;

import java.time.Clock;

class MapTokenStoreTest extends AbstractTokenStoreContract {
    @Override
    protected TokenStore createStore(Clock clock) {
        return new MapTokenStore(clock);
    }
}
