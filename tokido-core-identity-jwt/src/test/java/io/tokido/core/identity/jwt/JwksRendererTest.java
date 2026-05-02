package io.tokido.core.identity.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import io.tokido.core.identity.protocol.JsonWebKey;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class JwksRendererTest {

    @Test
    void rendersRsaPublicJwkWithRequiredFields() throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048)
                .keyID("kid-1")
                .algorithm(JWSAlgorithm.RS256)
                .generate();
        SigningKey signingKey = new SigningKey(
                "kid-1",
                SignatureAlgorithm.RS256,
                new KeyMaterial(rsaJwk.toRSAPrivateKey().getEncoded(), SignatureAlgorithm.RS256),
                KeyState.ACTIVE,
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"));

        JsonWebKey jwk = new JwksRenderer().render(signingKey);

        assertThat(jwk.kty()).isEqualTo("RSA");
        assertThat(jwk.kid()).isEqualTo("kid-1");
        assertThat(jwk.use()).isEqualTo("sig");
        assertThat(jwk.alg()).isEqualTo("RS256");
        assertThat(jwk.additionalParameters()).containsKey("n").containsKey("e");
        assertThat(jwk.additionalParameters()).doesNotContainKey("d")
                                              .doesNotContainKey("p")
                                              .doesNotContainKey("q");
    }
}
