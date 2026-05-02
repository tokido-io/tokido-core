package io.tokido.core.identity.engine.authorize;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScopeFilterTest {

    @Test
    void allowedScopesPassThrough() {
        Set<String> requested = Set.of("openid", "profile");
        Set<String> allowed = Set.of("openid", "profile", "email");
        assertThat(ScopeFilter.filter(requested, allowed)).isEqualTo(requested);
    }

    @Test
    void emptyRequestedPassThrough() {
        assertThat(ScopeFilter.filter(Set.of(), Set.of("openid"))).isEmpty();
    }

    @Test
    void unsupportedScopeThrows() {
        assertThatThrownBy(() ->
                ScopeFilter.filter(Set.of("openid", "admin"), Set.of("openid", "profile")))
                .isInstanceOf(ScopeFilter.UnsupportedScopeException.class);
    }

    @Test
    void exceptionExposesOffendingScope() {
        try {
            ScopeFilter.filter(Set.of("admin"), Set.of("openid"));
            org.assertj.core.api.Assertions.fail("should have thrown");
        } catch (ScopeFilter.UnsupportedScopeException e) {
            assertThat(e.scope()).isEqualTo("admin");
        }
    }

    @Test
    void emptyAllowedRejectsAnyRequested() {
        assertThatThrownBy(() -> ScopeFilter.filter(Set.of("openid"), Set.of()))
                .isInstanceOf(ScopeFilter.UnsupportedScopeException.class);
    }
}
