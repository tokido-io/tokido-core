package io.tokido.core.identity.engine.authorize;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RedirectUriMatcherTest {

    @Test
    void exactMatchReturnsTrue() {
        assertThat(RedirectUriMatcher.matches(
                "https://app.example/cb",
                Set.of("https://app.example/cb"))).isTrue();
    }

    @Test
    void differentCaseRejected() {
        assertThat(RedirectUriMatcher.matches(
                "https://APP.example/cb",
                Set.of("https://app.example/cb"))).isFalse();
    }

    @Test
    void trailingSlashRejected() {
        assertThat(RedirectUriMatcher.matches(
                "https://app.example/cb/",
                Set.of("https://app.example/cb"))).isFalse();
    }

    @Test
    void differentPathRejected() {
        assertThat(RedirectUriMatcher.matches(
                "https://app.example/other",
                Set.of("https://app.example/cb"))).isFalse();
    }

    @Test
    void nullSubmittedReturnsFalse() {
        assertThat(RedirectUriMatcher.matches(null, Set.of("https://app/cb"))).isFalse();
    }

    @Test
    void emptyRegisteredReturnsFalse() {
        assertThat(RedirectUriMatcher.matches("https://app/cb", Set.of())).isFalse();
    }

    @Test
    void multipleRegisteredAnyMatch() {
        Set<String> registered = Set.of(
                "https://app/cb",
                "https://app/cb2",
                "https://other/cb");
        assertThat(RedirectUriMatcher.matches("https://app/cb2", registered)).isTrue();
    }
}
