package io.tokido.core.identity.engine.authorize;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PkceTest {

    /** RFC 7636 Appendix B vector. */
    @Test
    void s256VerifiesRfcVector() {
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assertThat(Pkce.verify(verifier, challenge, "S256")).isTrue();
    }

    @Test
    void s256RejectsWrongVerifier() {
        String verifier = "wrong-verifier-1234567890123456789012345678901234567";
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assertThat(Pkce.verify(verifier, challenge, "S256")).isFalse();
    }

    @Test
    void plainVerifiesIdentity() {
        assertThat(Pkce.verify("same", "same", "plain")).isTrue();
        assertThat(Pkce.verify("same", "different", "plain")).isFalse();
    }

    @Test
    void nullMethodTreatedAsPlain() {
        assertThat(Pkce.verify("same", "same", null)).isTrue();
    }

    @Test
    void unknownMethodRejects() {
        assertThat(Pkce.verify("same", "same", "S512")).isFalse();
    }

    @Test
    void nullVerifierOrChallengeRejects() {
        assertThat(Pkce.verify(null, "x", "S256")).isFalse();
        assertThat(Pkce.verify("x", null, "S256")).isFalse();
    }
}
