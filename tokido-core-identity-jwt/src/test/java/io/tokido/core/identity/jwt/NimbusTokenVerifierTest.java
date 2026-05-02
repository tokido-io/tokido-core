package io.tokido.core.identity.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.KeyStore;
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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link NimbusTokenVerifier}: round-trip with
 * {@link NimbusTokenSigner}, plus the negative cases (kid mismatch, bad
 * signature, malformed token, expired token).
 */
class NimbusTokenVerifierTest {

    private static final Instant NOW = Instant.parse("2026-05-02T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private SigningKey rsaKey;

    @BeforeEach
    void generateRsaKey() throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048)
                .keyID("test-kid")
                .algorithm(JWSAlgorithm.RS256)
                .generate();
        byte[] pkcs8 = rsaJwk.toRSAPrivateKey().getEncoded();
        rsaKey = new SigningKey(
                "test-kid",
                SignatureAlgorithm.RS256,
                new KeyMaterial(pkcs8, SignatureAlgorithm.RS256),
                KeyState.ACTIVE,
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"));
    }

    @Test
    void rs256RoundTrip() {
        String payload = "{\"sub\":\"alice\",\"iss\":\"https://issuer.example/\",\"exp\":9999999999}";
        String compact = new NimbusTokenSigner().sign(payload, rsaKey);

        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(compact, oneKey(rsaKey));

        assertThat(claims).isNotEmpty();
        assertThat(claims.get("sub")).isEqualTo("alice");
        assertThat(claims.get("iss")).isEqualTo("https://issuer.example/");
    }

    @Test
    void kidMismatchReturnsEmptyMap() throws Exception {
        String compact = new NimbusTokenSigner().sign("{\"sub\":\"alice\"}", rsaKey);

        // Build a different keystore — same alg, same shape, different kid.
        RSAKey otherJwk = new RSAKeyGenerator(2048)
                .keyID("other-kid")
                .algorithm(JWSAlgorithm.RS256)
                .generate();
        byte[] pkcs8 = otherJwk.toRSAPrivateKey().getEncoded();
        SigningKey other = new SigningKey(
                "other-kid",
                SignatureAlgorithm.RS256,
                new KeyMaterial(pkcs8, SignatureAlgorithm.RS256),
                KeyState.ACTIVE,
                rsaKey.notBefore(), rsaKey.notAfter());

        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(compact, oneKey(other));

        assertThat(claims).isEmpty();
    }

    @Test
    void mutatedSignatureReturnsEmptyMap() {
        String compact = new NimbusTokenSigner().sign("{\"sub\":\"alice\"}", rsaKey);
        // Mutate a character roughly in the middle of the signature segment so
        // we modify high-order signature bits (avoids Base64URL padding edge
        // cases where the last char's low-order bits decode the same byte).
        int lastDot = compact.lastIndexOf('.');
        int mutateIdx = lastDot + 8;
        char orig = compact.charAt(mutateIdx);
        char swapped = orig == 'A' ? 'B' : 'A';
        String tampered = compact.substring(0, mutateIdx) + swapped + compact.substring(mutateIdx + 1);
        // Sanity: we must have changed the signature, not the payload.
        assertThat(tampered).isNotEqualTo(compact);

        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(tampered, oneKey(rsaKey));

        assertThat(claims).isEmpty();
    }

    @Test
    void malformedTokenReturnsEmptyMap() {
        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify("not.a.jws", oneKey(rsaKey));
        assertThat(claims).isEmpty();
    }

    @Test
    void completelyBogusInputReturnsEmptyMap() {
        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify("garbage", oneKey(rsaKey));
        assertThat(claims).isEmpty();
    }

    @Test
    void expiredTokenReturnsEmptyMap() {
        // exp is one second before the fixed clock.
        long expEpoch = NOW.minusSeconds(1).getEpochSecond();
        String payload = "{\"sub\":\"alice\",\"exp\":" + expEpoch + "}";
        String compact = new NimbusTokenSigner().sign(payload, rsaKey);

        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(compact, oneKey(rsaKey));

        assertThat(claims).isEmpty();
    }

    @Test
    void notYetValidTokenReturnsEmptyMap() {
        // nbf is one second after the fixed clock.
        long nbfEpoch = NOW.plusSeconds(60).getEpochSecond();
        String payload = "{\"sub\":\"alice\",\"nbf\":" + nbfEpoch + "}";
        String compact = new NimbusTokenSigner().sign(payload, rsaKey);

        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(compact, oneKey(rsaKey));

        assertThat(claims).isEmpty();
    }

    @Test
    void retiredKeyStillVerifies() {
        // Sign with an active key; copy of the same key in RETIRED state must verify.
        String compact = new NimbusTokenSigner().sign("{\"sub\":\"alice\"}", rsaKey);
        SigningKey retired = new SigningKey(
                rsaKey.kid(), rsaKey.alg(), rsaKey.material(),
                KeyState.RETIRED, rsaKey.notBefore(), rsaKey.notAfter());

        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(compact, oneKey(retired));

        assertThat(claims).isNotEmpty();
        assertThat(claims.get("sub")).isEqualTo("alice");
    }

    @Test
    void es256RoundTrip() throws Exception {
        ECKey ecJwk = new ECKeyGenerator(Curve.P_256)
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

        String compact = new NimbusTokenSigner().sign("{\"sub\":\"bob\"}", ecKey);
        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(compact, oneKey(ecKey));

        assertThat(claims).isNotEmpty();
        assertThat(claims.get("sub")).isEqualTo("bob");
    }

    @Test
    void edDsaRoundTrip() throws Exception {
        // Generate Ed25519 keypair using Java's built-in provider.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = gen.generateKeyPair();
        EdECPrivateKey priv = (EdECPrivateKey) kp.getPrivate();
        EdECPublicKey pub = (EdECPublicKey) kp.getPublic();

        byte[] privBytes = priv.getBytes().orElseThrow();
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

        String compact = new NimbusTokenSigner().sign("{\"sub\":\"carol\"}", edKey);
        Map<String, Object> claims = new NimbusTokenVerifier(FIXED_CLOCK)
                .verify(compact, oneKey(edKey));

        assertThat(claims).isNotEmpty();
        assertThat(claims.get("sub")).isEqualTo("carol");
    }

    @Test
    void defaultConstructorUsesSystemClock() {
        // Smoke test — no explicit clock, verifies a freshly-signed token.
        String payload = "{\"sub\":\"alice\",\"exp\":9999999999}";
        String compact = new NimbusTokenSigner().sign(payload, rsaKey);

        Map<String, Object> claims = new NimbusTokenVerifier()
                .verify(compact, oneKey(rsaKey));

        assertThat(claims).isNotEmpty();
        assertThat(claims.get("sub")).isEqualTo("alice");
    }

    private static KeyStore oneKey(SigningKey k) {
        return new KeyStore() {
            @Override public SigningKey activeSigningKey(SignatureAlgorithm a) { return k; }
            @Override public Set<SigningKey> allKeys() { return Set.of(k); }
        };
    }
}
