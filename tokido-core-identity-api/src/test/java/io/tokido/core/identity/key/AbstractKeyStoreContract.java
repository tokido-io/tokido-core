package io.tokido.core.identity.key;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Contract tests for any {@link KeyStore} implementation. Subclasses provide
 * a {@link #createStore(Set)} factory that returns a {@link KeyStore} pre-seeded
 * with the given keys. Every concrete implementation in tokido-core-test (M2)
 * and downstream (Project B JPA, Project C DynamoDB) extends this class.
 *
 * <p>The contract is the public source of truth for what a {@link KeyStore}
 * must do; if a behavior should be required, it has a test here.
 */
public abstract class AbstractKeyStoreContract {

    /** Subclass-provided factory returning a store seeded with {@code keys}. */
    protected abstract KeyStore createStore(Set<SigningKey> keys);

    private SigningKey sampleActive(String kid, SignatureAlgorithm alg) {
        return new SigningKey(
                kid, alg,
                new KeyMaterial(new byte[]{1, 2, 3}, alg),
                KeyState.ACTIVE,
                Instant.parse("2026-05-01T00:00:00Z"),
                Instant.parse("2026-08-01T00:00:00Z"));
    }

    private SigningKey sampleRetired(String kid, SignatureAlgorithm alg) {
        return new SigningKey(
                kid, alg,
                new KeyMaterial(new byte[]{4, 5, 6}, alg),
                KeyState.RETIRED,
                Instant.parse("2026-02-01T00:00:00Z"),
                Instant.parse("2026-05-01T00:00:00Z"));
    }

    @Test
    void activeSigningKeyReturnsTheActiveKeyForAlgorithm() {
        SigningKey active = sampleActive("kid-active", SignatureAlgorithm.RS256);
        SigningKey retired = sampleRetired("kid-retired", SignatureAlgorithm.RS256);
        KeyStore store = createStore(Set.of(active, retired));

        assertThat(store.activeSigningKey(SignatureAlgorithm.RS256)).isEqualTo(active);
    }

    @Test
    void activeSigningKeyThrowsWhenNoActiveKeyForAlgorithm() {
        SigningKey rsActive = sampleActive("kid-rs", SignatureAlgorithm.RS256);
        KeyStore store = createStore(Set.of(rsActive));

        assertThatThrownBy(() -> store.activeSigningKey(SignatureAlgorithm.ES256))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void allKeysReturnsActiveAndRetired() {
        SigningKey active = sampleActive("kid-active", SignatureAlgorithm.RS256);
        SigningKey retired = sampleRetired("kid-retired", SignatureAlgorithm.RS256);
        KeyStore store = createStore(Set.of(active, retired));

        assertThat(store.allKeys()).containsExactlyInAnyOrder(active, retired);
    }

    @Test
    void allKeysIsImmutable() {
        SigningKey active = sampleActive("kid-active", SignatureAlgorithm.RS256);
        KeyStore store = createStore(Set.of(active));

        Set<SigningKey> snapshot = store.allKeys();
        assertThatThrownBy(() -> snapshot.add(sampleActive("k2", SignatureAlgorithm.ES256)))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
