package io.tokido.core.identity.jwt;

import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InMemoryKeyStoreTest {

    @Test
    void constructorGeneratesActiveRs256Key() {
        InMemoryKeyStore store = new InMemoryKeyStore();
        SigningKey active = store.activeSigningKey(SignatureAlgorithm.RS256);
        assertThat(active.state()).isEqualTo(KeyState.ACTIVE);
        assertThat(active.alg()).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(active.kid()).isNotBlank();
    }

    @Test
    void allKeysContainsTheGeneratedKey() {
        InMemoryKeyStore store = new InMemoryKeyStore();
        SigningKey active = store.activeSigningKey(SignatureAlgorithm.RS256);
        assertThat(store.allKeys()).containsExactly(active);
    }

    @Test
    void unsupportedAlgorithmThrows() {
        InMemoryKeyStore store = new InMemoryKeyStore();
        assertThatThrownBy(() -> store.activeSigningKey(SignatureAlgorithm.ES256))
                .isInstanceOf(IllegalStateException.class);
    }
}
