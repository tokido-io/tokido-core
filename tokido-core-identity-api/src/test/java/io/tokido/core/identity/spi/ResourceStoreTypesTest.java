package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class ResourceStoreTypesTest {

    @Test
    void identityScopeMustHaveNonBlankName() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new IdentityScope("", "Display", Set.of()));
    }

    @Test
    void identityScopeExposesUserClaimNames() {
        IdentityScope s = new IdentityScope("profile", "User profile", Set.of("name", "given_name"));
        assertThat(s.userClaimNames()).containsExactlyInAnyOrder("name", "given_name");
    }

    @Test
    void resourceScopeAcceptsNullDisplayName() {
        ResourceScope s = new ResourceScope("api.read", null);
        assertThat(s.displayName()).isNull();
    }

    @Test
    void protectedResourceRequiresNonNullScopes() {
        assertThatNullPointerException().isThrownBy(
                () -> new ProtectedResource("api1", "API One", null));
    }

    @Test
    void protectedResourceCopiesScopesToImmutable() {
        ProtectedResource r = new ProtectedResource("api1", "API One",
                Set.of(new ResourceScope("api.read", "Read"),
                       new ResourceScope("api.write", "Write")));
        assertThat(r.scopes()).hasSize(2);
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> r.scopes().add(new ResourceScope("api.delete", "Delete")))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @org.junit.jupiter.api.Nested
    class SmokeContract extends AbstractResourceStoreContract {
        @Override
        protected ResourceStore createStore(java.util.Set<IdentityScope> ids,
                                            java.util.Set<ProtectedResource> rs) {
            java.util.Map<String, IdentityScope> idMap = new java.util.HashMap<>();
            for (IdentityScope s : ids) idMap.put(s.name(), s);
            java.util.Map<String, ProtectedResource> rMap = new java.util.HashMap<>();
            for (ProtectedResource r : rs) rMap.put(r.name(), r);
            java.util.Map<String, IdentityScope> idSnap = java.util.Map.copyOf(idMap);
            java.util.Map<String, ProtectedResource> rSnap = java.util.Map.copyOf(rMap);
            return new ResourceStore() {
                @Override
                public IdentityScope findIdentityScope(String name) {
                    return idSnap.get(name);
                }
                @Override
                public ProtectedResource findProtectedResource(String name) {
                    return rSnap.get(name);
                }
                @Override
                public java.util.Set<IdentityScope> findIdentityScopesByName(java.util.Set<String> names) {
                    java.util.Set<IdentityScope> out = new java.util.HashSet<>();
                    for (String n : names) {
                        IdentityScope s = idSnap.get(n);
                        if (s != null) out.add(s);
                    }
                    return java.util.Set.copyOf(out);
                }
                @Override
                public java.util.Set<ProtectedResource> findResourcesByScope(java.util.Set<String> scopeNames) {
                    java.util.Set<ProtectedResource> out = new java.util.HashSet<>();
                    for (ProtectedResource r : rSnap.values()) {
                        for (ResourceScope s : r.scopes()) {
                            if (scopeNames.contains(s.name())) {
                                out.add(r);
                                break;
                            }
                        }
                    }
                    return java.util.Set.copyOf(out);
                }
            };
        }
    }
}
