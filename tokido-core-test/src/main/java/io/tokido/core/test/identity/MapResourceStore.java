package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.ProtectedResource;
import io.tokido.core.identity.spi.ResourceScope;
import io.tokido.core.identity.spi.ResourceStore;
import org.apiguardian.api.API;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * In-memory {@link ResourceStore} backed by two hash maps.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class MapResourceStore implements ResourceStore {

    private final Map<String, IdentityScope> identityByName;
    private final Map<String, ProtectedResource> resourceByName;

    public MapResourceStore(Set<IdentityScope> identityScopes,
                            Set<ProtectedResource> protectedResources) {
        Objects.requireNonNull(identityScopes, "identityScopes");
        Objects.requireNonNull(protectedResources, "protectedResources");
        Map<String, IdentityScope> ids = new HashMap<>();
        for (IdentityScope s : identityScopes) ids.put(s.name(), s);
        Map<String, ProtectedResource> rs = new HashMap<>();
        for (ProtectedResource r : protectedResources) rs.put(r.name(), r);
        this.identityByName = Map.copyOf(ids);
        this.resourceByName = Map.copyOf(rs);
    }

    @Override public IdentityScope findIdentityScope(String name) { return identityByName.get(name); }
    @Override public ProtectedResource findProtectedResource(String name) { return resourceByName.get(name); }

    @Override
    public Set<IdentityScope> findIdentityScopesByName(Set<String> names) {
        Set<IdentityScope> out = new HashSet<>();
        for (String n : names) {
            IdentityScope s = identityByName.get(n);
            if (s != null) out.add(s);
        }
        return Set.copyOf(out);
    }

    @Override
    public Set<ProtectedResource> findResourcesByScope(Set<String> scopeNames) {
        Set<ProtectedResource> out = new HashSet<>();
        for (ProtectedResource r : resourceByName.values()) {
            for (ResourceScope s : r.scopes()) {
                if (scopeNames.contains(s.name())) {
                    out.add(r);
                    break;
                }
            }
        }
        return Set.copyOf(out);
    }
}
