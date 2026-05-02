package io.tokido.core.test.identity;

import io.tokido.core.identity.key.AbstractKeyStoreContract;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SigningKey;

import java.util.Set;

class MapKeyStoreTest extends AbstractKeyStoreContract {
    @Override
    protected KeyStore createStore(Set<SigningKey> keys) {
        return new MapKeyStore(keys);
    }
}
