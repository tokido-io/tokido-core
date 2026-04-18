package io.tokido.core.test;

import io.tokido.core.StoredSecret;
import io.tokido.core.spi.SecretStore;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link SecretStore} for testing.
 * Thread-safe via {@link ConcurrentHashMap}. No encryption — stores raw bytes.
 */
public class InMemorySecretStore implements SecretStore {

    private final Map<String, StoredSecret> store = new ConcurrentHashMap<>();

    private static String key(String userId, String factorType) {
        return userId + ":" + factorType;
    }

    @Override
    public void store(String userId, String factorType, byte[] secret, Map<String, Object> metadata) {
        store.put(key(userId, factorType), new StoredSecret(secret, new HashMap<>(metadata)));
    }

    @Override
    public StoredSecret load(String userId, String factorType) {
        return store.get(key(userId, factorType));
    }

    @Override
    public void update(String userId, String factorType, Map<String, Object> metadata) {
        String k = key(userId, factorType);
        StoredSecret existing = store.get(k);
        if (existing != null) {
            Map<String, Object> merged = new HashMap<>(existing.metadata());
            merged.putAll(metadata);
            store.put(k, new StoredSecret(existing.secret(), merged));
        }
    }

    @Override
    public void delete(String userId, String factorType) {
        store.remove(key(userId, factorType));
    }

    @Override
    public boolean exists(String userId, String factorType) {
        return store.containsKey(key(userId, factorType));
    }

    // --- Test inspection methods ---

    public boolean hasSecret(String userId, String factorType) {
        return exists(userId, factorType);
    }

    public StoredSecret inspect(String userId, String factorType) {
        return load(userId, factorType);
    }

    public int size() {
        return store.size();
    }

    public void clear() {
        store.clear();
    }
}
