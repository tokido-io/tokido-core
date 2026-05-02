package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class ConsentStoreTypesTest {

    @Test
    void consentRejectsBlankSubjectId() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new Consent("", "client", Set.of("openid"), Instant.now()));
    }

    @Test
    void consentRejectsBlankClientId() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new Consent("sub", "", Set.of("openid"), Instant.now()));
    }

    @Test
    void consentRejectsNullExpiration() {
        assertThatNullPointerException().isThrownBy(
                () -> new Consent("sub", "client", Set.of("openid"), null));
    }

    @Test
    void consentCopiesScopesToImmutable() {
        Consent c = new Consent("sub", "client", Set.of("openid"), Instant.now().plusSeconds(60));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> c.scopes().add("api"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @org.junit.jupiter.api.Nested
    class SmokeContract extends AbstractConsentStoreContract {
        @Override
        protected ConsentStore createStore() {
            java.util.Map<String, Consent> backing = new java.util.HashMap<>();
            return new ConsentStore() {
                private String key(String s, String c) { return s + "|" + c; }
                @Override
                public Consent find(String s, String c) {
                    return backing.get(key(s, c));
                }
                @Override
                public void store(Consent consent) {
                    backing.put(key(consent.subjectId(), consent.clientId()), consent);
                }
                @Override
                public void remove(String s, String c) {
                    backing.remove(key(s, c));
                }
            };
        }
    }
}
