package io.tokido.core.identity.protocol;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class DiscoveryAndJwksTest {

    @Test
    void jsonWebKeyRejectsBlankKid() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new JsonWebKey("RSA", "", "sig", "RS256", Map.of()));
    }

    @Test
    void jsonWebKeyRejectsNullKty() {
        assertThatNullPointerException().isThrownBy(
                () -> new JsonWebKey(null, "kid-1", "sig", "RS256", Map.of()));
    }

    @Test
    void jsonWebKeyAcceptsNullableUseAndAlg() {
        JsonWebKey k = new JsonWebKey("RSA", "kid-1", null, null, Map.of());
        assertThat(k.use()).isNull();
        assertThat(k.alg()).isNull();
    }

    @Test
    void jsonWebKeyCopiesAdditionalParametersToImmutable() {
        JsonWebKey k = new JsonWebKey("RSA", "kid-1", "sig", "RS256",
                Map.of("n", "modulus-bytes", "e", "AQAB"));
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> k.additionalParameters().put("k", "v"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void jsonWebKeySetCopiesKeysToImmutable() {
        JsonWebKey k = new JsonWebKey("RSA", "kid-1", "sig", "RS256", Map.of());
        JsonWebKeySet set = new JsonWebKeySet(Set.of(k));
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> set.keys().add(k))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void discoveryDocumentRequiresMandatoryEndpoints() {
        assertThatNullPointerException().isThrownBy(() ->
                new DiscoveryDocument(
                        null,
                        URI.create("https://i/auth"),
                        URI.create("https://i/token"),
                        null, URI.create("https://i/jwks"),
                        null, null, null,
                        Set.of("code"), Set.of("authorization_code"),
                        Set.of("public"), Set.of("RS256"),
                        Set.of("openid"), Set.of("client_secret_basic"),
                        Set.of("sub"), Map.of()));
    }

    @Test
    void discoveryDocumentNullableEndpointsAccepted() {
        DiscoveryDocument doc = new DiscoveryDocument(
                URI.create("https://issuer.example/"),
                URI.create("https://issuer.example/auth"),
                URI.create("https://issuer.example/token"),
                null, // userinfoEndpoint nullable
                URI.create("https://issuer.example/jwks"),
                null, null, null, // introspection, revocation, end_session nullable
                Set.of("code"),
                Set.of("authorization_code"),
                Set.of("public"),
                Set.of("RS256"),
                null, null, null, // optional collections
                Map.of());
        assertThat(doc.userinfoEndpoint()).isNull();
        assertThat(doc.scopesSupported()).isEmpty();
        assertThat(doc.tokenEndpointAuthMethodsSupported()).isEmpty();
        assertThat(doc.claimsSupported()).isEmpty();
    }

    @Test
    void discoveryDocumentCopiesCollectionsToImmutable() {
        DiscoveryDocument doc = new DiscoveryDocument(
                URI.create("https://issuer.example/"),
                URI.create("https://issuer.example/auth"),
                URI.create("https://issuer.example/token"),
                URI.create("https://issuer.example/userinfo"),
                URI.create("https://issuer.example/jwks"),
                null, null, null,
                Set.of("code"),
                Set.of("authorization_code", "refresh_token"),
                Set.of("public"),
                Set.of("RS256", "ES256"),
                Set.of("openid", "profile"),
                Set.of("client_secret_basic"),
                Set.of("sub", "name"),
                Map.of("require_request_uri_registration", false));
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> doc.responseTypesSupported().add("token"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
