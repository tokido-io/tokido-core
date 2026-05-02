package io.tokido.core.identity.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
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
    void signEs256RoundTrip() throws Exception {
        ECKey ecJwk = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                .keyID("ec-kid")
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        byte[] pkcs8 = ecJwk.toECPrivateKey().getEncoded();
        SigningKey ecKey = new SigningKey(
                "ec-kid",
                SignatureAlgorithm.ES256,
                new KeyMaterial(pkcs8, SignatureAlgorithm.ES256),
                KeyState.ACTIVE,
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"));

        NimbusTokenSigner signer = new NimbusTokenSigner();
        String compactJws = signer.sign("{\"sub\":\"bob\"}", ecKey);

        JWSObject parsed = JWSObject.parse(compactJws);
        assertThat(parsed.verify(new ECDSAVerifier(ecJwk.toECPublicKey()))).isTrue();
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void signEdDsaRoundTrip() throws Exception {
        // Generate Ed25519 keypair using Java's built-in provider (no Tink required)
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = gen.generateKeyPair();
        EdECPrivateKey priv = (EdECPrivateKey) kp.getPrivate();
        EdECPublicKey pub = (EdECPublicKey) kp.getPublic();

        byte[] privBytes = priv.getBytes().orElseThrow();
        // Derive compressed public key bytes (little-endian with sign bit)
        EdECPoint point = pub.getPoint();
        byte[] yBytes = point.getY().toByteArray();
        byte[] pubLE = new byte[32];
        for (int i = 0; i < 32; i++) {
            int srcIdx = yBytes.length - 1 - i;
            pubLE[i] = srcIdx >= 0 ? yBytes[srcIdx] : 0;
        }
        if (point.isXOdd()) pubLE[31] |= (byte) 0x80;

        OctetKeyPair okp = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(pubLE))
                .d(Base64URL.encode(privBytes))
                .keyID("ed-kid")
                .build();

        byte[] okpJson = okp.toJSONString().getBytes(StandardCharsets.UTF_8);
        SigningKey edKey = new SigningKey(
                "ed-kid",
                SignatureAlgorithm.EDDSA,
                new KeyMaterial(okpJson, SignatureAlgorithm.EDDSA),
                KeyState.ACTIVE,
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"));

        NimbusTokenSigner signer = new NimbusTokenSigner();
        String compactJws = signer.sign("{\"sub\":\"carol\"}", edKey);

        JWSObject parsed = JWSObject.parse(compactJws);
        assertThat(parsed.verify(new Ed25519Verifier(okp.toPublicJWK()))).isTrue();
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
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
