package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for any {@link ResourceStore} implementation. Subclasses
 * provide a {@link #createStore(Set, Set)} factory that returns a store
 * seeded with the given identity scopes and protected resources.
 */
public abstract class AbstractResourceStoreContract {

    protected abstract ResourceStore createStore(Set<IdentityScope> identityScopes,
                                                 Set<ProtectedResource> protectedResources);

    private IdentityScope openid() {
        return new IdentityScope("openid", "OpenID Connect", Set.of("sub"));
    }

    private IdentityScope profile() {
        return new IdentityScope("profile", "Profile", Set.of("name", "given_name", "family_name"));
    }

    private ProtectedResource api1() {
        return new ProtectedResource("api1", "API One",
                Set.of(new ResourceScope("api1.read", "Read"),
                       new ResourceScope("api1.write", "Write")));
    }

    @Test
    void findIdentityScopeReturnsSeededScope() {
        ResourceStore store = createStore(Set.of(openid(), profile()), Set.of());
        assertThat(store.findIdentityScope("openid")).isEqualTo(openid());
    }

    @Test
    void findIdentityScopeReturnsNullForUnknown() {
        ResourceStore store = createStore(Set.of(openid()), Set.of());
        assertThat(store.findIdentityScope("nope")).isNull();
    }

    @Test
    void findProtectedResourceReturnsSeeded() {
        ResourceStore store = createStore(Set.of(), Set.of(api1()));
        assertThat(store.findProtectedResource("api1")).isEqualTo(api1());
    }

    @Test
    void findIdentityScopesByNameFiltersUnknown() {
        ResourceStore store = createStore(Set.of(openid(), profile()), Set.of());
        assertThat(store.findIdentityScopesByName(Set.of("openid", "nope")))
                .containsExactly(openid());
    }

    @Test
    void findResourcesByScopeReturnsResourcesWhoseScopesIntersect() {
        ResourceStore store = createStore(Set.of(), Set.of(api1()));
        assertThat(store.findResourcesByScope(Set.of("api1.read", "api1.delete")))
                .containsExactly(api1());
    }
}
