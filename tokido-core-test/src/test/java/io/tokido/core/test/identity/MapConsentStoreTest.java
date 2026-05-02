package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.AbstractConsentStoreContract;
import io.tokido.core.identity.spi.ConsentStore;

class MapConsentStoreTest extends AbstractConsentStoreContract {
    @Override
    protected ConsentStore createStore() {
        return new MapConsentStore();
    }
}
