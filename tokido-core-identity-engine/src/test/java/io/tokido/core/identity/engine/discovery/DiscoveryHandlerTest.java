package io.tokido.core.identity.engine.discovery;

import io.tokido.core.identity.protocol.DiscoveryDocument;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryHandlerTest {

    @Test
    void buildsDocumentWithStandardEndpoints() {
        URI issuer = URI.create("https://issuer.example/");
        DiscoveryDocument doc = new DiscoveryHandler(issuer).build();

        assertThat(doc.issuer()).isEqualTo(issuer);
        assertThat(doc.authorizationEndpoint()).isEqualTo(URI.create("https://issuer.example/authorize"));
        assertThat(doc.tokenEndpoint()).isEqualTo(URI.create("https://issuer.example/token"));
        assertThat(doc.userinfoEndpoint()).isEqualTo(URI.create("https://issuer.example/userinfo"));
        assertThat(doc.jwksUri()).isEqualTo(URI.create("https://issuer.example/jwks"));
        assertThat(doc.responseTypesSupported()).contains("code");
        assertThat(doc.grantTypesSupported())
                .contains("authorization_code", "refresh_token", "client_credentials");
        assertThat(doc.subjectTypesSupported()).contains("public");
        assertThat(doc.idTokenSigningAlgValuesSupported()).contains("RS256");
        assertThat(doc.tokenEndpointAuthMethodsSupported())
                .contains("client_secret_basic", "client_secret_post", "none");
    }

    @Test
    void issuerWithoutTrailingSlashStillProducesEndpoints() {
        URI issuer = URI.create("https://issuer.example");
        DiscoveryDocument doc = new DiscoveryHandler(issuer).build();
        assertThat(doc.tokenEndpoint().toString()).isEqualTo("https://issuer.example/token");
    }
}
