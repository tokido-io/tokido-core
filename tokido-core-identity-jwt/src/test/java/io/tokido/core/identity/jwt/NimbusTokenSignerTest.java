package io.tokido.core.identity.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NimbusTokenSignerTest {

    private RSAKey rsaJwk;
    private SigningKey signingKey;

    @BeforeEach
    void generateKey() throws Exception {
        rsaJwk = new RSAKeyGenerator(2048)
                .keyID("test-kid")
                .algorithm(JWSAlgorithm.RS256)
                .generate();
        byte[] pkcs8 = rsaJwk.toRSAPrivateKey().getEncoded();
        signingKey = new SigningKey(
                "test-kid",
                SignatureAlgorithm.RS256,
                new KeyMaterial(pkcs8, SignatureAlgorithm.RS256),
                KeyState.ACTIVE,
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"));
    }

    @Test
    void signAndVerifyRoundTrip() throws Exception {
        NimbusTokenSigner signer = new NimbusTokenSigner();
        String payload = "{\"iss\":\"https://issuer\",\"sub\":\"alice\"}";
        String compactJws = signer.sign(payload, signingKey);

        JWSObject parsed = JWSObject.parse(compactJws);
        assertThat(parsed.verify(new RSASSAVerifier(rsaJwk.toRSAPublicKey()))).isTrue();
        assertThat(parsed.getPayload().toString()).isEqualTo(payload);
        assertThat(parsed.getHeader().getKeyID()).isEqualTo("test-kid");
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void signRejectsRetiredKey() {
        SigningKey retired = new SigningKey(
                signingKey.kid(),
                signingKey.alg(),
                signingKey.material(),
                KeyState.RETIRED,
                signingKey.notBefore(),
                signingKey.notAfter());
        NimbusTokenSigner signer = new NimbusTokenSigner();
        assertThatThrownBy(() -> signer.sign("{}", retired))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("RETIRED");
    }
}
