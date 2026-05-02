package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.AbstractResourceStoreContract;
import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.ProtectedResource;
import io.tokido.core.identity.spi.ResourceStore;

import java.util.Set;

class MapResourceStoreTest extends AbstractResourceStoreContract {
    @Override
    protected ResourceStore createStore(Set<IdentityScope> identityScopes,
                                        Set<ProtectedResource> protectedResources) {
        return new MapResourceStore(identityScopes, protectedResources);
    }
}
