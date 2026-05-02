package io.tokido.core.identity.key;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class KeyStoreTypesTest {

    @Test
    void keyMaterialAcceptsBytesAndAlg() {
        KeyMaterial m = new KeyMaterial(new byte[]{1, 2, 3}, SignatureAlgorithm.RS256);
        assertThat(m.bytes()).containsExactly(1, 2, 3);
        assertThat(m.alg()).isEqualTo(SignatureAlgorithm.RS256);
    }

    @Test
    void keyMaterialRejectsNullBytes() {
        assertThatNullPointerException().isThrownBy(
                () -> new KeyMaterial(null, SignatureAlgorithm.RS256));
    }

    @Test
    void keyMaterialRejectsNullAlg() {
        assertThatNullPointerException().isThrownBy(
                () -> new KeyMaterial(new byte[]{1}, null));
    }

    @Test
    void signingKeyExposesAllFields() {
        Instant nbf = Instant.parse("2026-05-01T00:00:00Z");
        Instant exp = Instant.parse("2026-08-01T00:00:00Z");
        KeyMaterial mat = new KeyMaterial(new byte[]{42}, SignatureAlgorithm.RS256);
        SigningKey k = new SigningKey("kid-1", SignatureAlgorithm.RS256, mat, KeyState.ACTIVE, nbf, exp);
        assertThat(k.kid()).isEqualTo("kid-1");
        assertThat(k.alg()).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(k.material()).isSameAs(mat);
        assertThat(k.state()).isEqualTo(KeyState.ACTIVE);
        assertThat(k.notBefore()).isEqualTo(nbf);
        assertThat(k.notAfter()).isEqualTo(exp);
    }

    @Test
    void signingKeyRejectsBlankKid() {
        KeyMaterial mat = new KeyMaterial(new byte[]{42}, SignatureAlgorithm.RS256);
        assertThatIllegalArgumentException().isThrownBy(
                () -> new SigningKey("", SignatureAlgorithm.RS256, mat, KeyState.ACTIVE,
                        Instant.now(), Instant.now().plusSeconds(60)));
    }

    @Test
    void signingKeyRejectsAlgMismatch() {
        KeyMaterial mat = new KeyMaterial(new byte[]{42}, SignatureAlgorithm.RS256);
        assertThatIllegalArgumentException().isThrownBy(
                () -> new SigningKey("kid", SignatureAlgorithm.ES256, mat, KeyState.ACTIVE,
                        Instant.now(), Instant.now().plusSeconds(60)));
    }

    @Test
    void signingKeyRejectsNotAfterBeforeNotBefore() {
        KeyMaterial mat = new KeyMaterial(new byte[]{42}, SignatureAlgorithm.RS256);
        Instant t = Instant.parse("2026-05-01T00:00:00Z");
        assertThatIllegalArgumentException().isThrownBy(
                () -> new SigningKey("kid", SignatureAlgorithm.RS256, mat, KeyState.ACTIVE, t, t));
    }

    /**
     * Smoke runner that drives {@link AbstractKeyStoreContract} against a tiny
     * Set-backed in-memory KeyStore. The "real" in-memory KeyStore lands in
     * tokido-core-test at M2; this is just enough to exercise the contract for
     * coverage.
     */
    @org.junit.jupiter.api.Nested
    class SmokeContract extends AbstractKeyStoreContract {
        @Override
        protected KeyStore createStore(java.util.Set<SigningKey> keys) {
            java.util.Set<SigningKey> snapshot = java.util.Set.copyOf(keys);
            return new KeyStore() {
                @Override
                public SigningKey activeSigningKey(SignatureAlgorithm alg) {
                    return snapshot.stream()
                            .filter(k -> k.state() == KeyState.ACTIVE && k.alg() == alg)
                            .findFirst()
                            .orElseThrow(() ->
                                    new IllegalStateException("no active key for " + alg));
                }

                @Override
                public java.util.Set<SigningKey> allKeys() {
                    return snapshot;
                }
            };
        }
    }
}
