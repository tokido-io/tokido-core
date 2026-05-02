package io.tokido.core.test;

import io.tokido.core.StoredSecret;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InMemorySecretStoreTest {

    @Test
    void storeAndLoadRoundTrip() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.store("alice", "totp", new byte[]{1, 2, 3}, Map.of("k", "v"));
        StoredSecret loaded = store.load("alice", "totp");
        assertThat(loaded).isNotNull();
        assertThat(loaded.secret()).containsExactly(1, 2, 3);
    }

    @Test
    void loadReturnsNullForUnknown() {
        InMemorySecretStore store = new InMemorySecretStore();
        assertThat(store.load("alice", "totp")).isNull();
    }

    @Test
    void existsReturnsTrueAfterStore() {
        InMemorySecretStore store = new InMemorySecretStore();
        assertThat(store.exists("alice", "totp")).isFalse();
        store.store("alice", "totp", new byte[]{}, Map.of());
        assertThat(store.exists("alice", "totp")).isTrue();
    }

    @Test
    void deleteRemovesEntry() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.store("alice", "totp", new byte[]{1}, Map.of());
        store.delete("alice", "totp");
        assertThat(store.exists("alice", "totp")).isFalse();
        assertThat(store.load("alice", "totp")).isNull();
    }

    @Test
    void updateMergesMetadata() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.store("alice", "totp", new byte[]{1}, Map.of("a", "1"));
        store.update("alice", "totp", Map.of("b", "2"));
        StoredSecret loaded = store.load("alice", "totp");
        assertThat(loaded.metadata()).containsEntry("a", "1").containsEntry("b", "2");
    }

    @Test
    void updateNoopsForUnknownEntry() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.update("alice", "totp", Map.of("b", "2")); // should not throw
        assertThat(store.exists("alice", "totp")).isFalse();
    }

    @Test
    void hasSecretDelegatesToExists() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.store("alice", "totp", new byte[]{}, Map.of());
        assertThat(store.hasSecret("alice", "totp")).isTrue();
    }

    @Test
    void inspectReturnsSecret() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.store("alice", "totp", new byte[]{7}, Map.of());
        assertThat(store.inspect("alice", "totp").secret()).containsExactly(7);
    }

    @Test
    void sizeAndClear() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.store("alice", "totp", new byte[]{}, Map.of());
        store.store("bob", "totp", new byte[]{}, Map.of());
        assertThat(store.size()).isEqualTo(2);
        store.clear();
        assertThat(store.size()).isZero();
    }
}
