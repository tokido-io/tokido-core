package io.tokido.core.test.identity;

import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import org.apiguardian.api.API;

import java.util.Objects;
import java.util.Set;

/**
 * In-memory {@link KeyStore} backed by a frozen seed {@code Set<SigningKey>}.
 * Unlike {@code InMemoryKeyStore} in tokido-core-identity-jwt, this variant
 * accepts pre-built keys at construction — useful for tests that need
 * specific kids, multiple keys, or RETIRED states.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class MapKeyStore implements KeyStore {

    private final Set<SigningKey> snapshot;

    public MapKeyStore(Set<SigningKey> keys) {
        this.snapshot = Set.copyOf(Objects.requireNonNull(keys, "keys"));
    }

    @Override
    public SigningKey activeSigningKey(SignatureAlgorithm alg) {
        return snapshot.stream()
                .filter(k -> k.state() == KeyState.ACTIVE && k.alg() == alg)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("no active key for " + alg));
    }

    @Override public Set<SigningKey> allKeys() { return snapshot; }
}
