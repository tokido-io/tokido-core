package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.AbstractUserStoreContract;
import io.tokido.core.identity.spi.User;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.identity.spi.UserStore;

import java.util.Map;
import java.util.Set;

class MapUserStoreTest extends AbstractUserStoreContract {
    @Override
    protected UserStore createStore(Set<User> users,
                                    Map<String, String> passwords,
                                    Map<String, User> federatedMappings,
                                    Map<String, Set<UserClaim>> claimsBySubject) {
        return new MapUserStore(users, passwords, federatedMappings, claimsBySubject);
    }
}
