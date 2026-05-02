package io.tokido.core.identity.jwt;

import com.nimbusds.jose.jwk.RSAKey;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import io.tokido.core.identity.protocol.JsonWebKey;
import org.apiguardian.api.API;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Renders {@link SigningKey} values as RFC 7517 {@link JsonWebKey} entries
 * suitable for the JWKS endpoint. Always emits public-only fields.
 *
 * <p>Currently supports RS256 only at M2.RC1.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class JwksRenderer {

    /**
     * Convert a {@link SigningKey} to a public-only {@link JsonWebKey}.
     *
     * @param key the signing key
     * @return public JWK
     * @throws IllegalArgumentException if the algorithm is not supported
     */
    public JsonWebKey render(SigningKey key) {
        if (key.alg() != SignatureAlgorithm.RS256) {
            throw new IllegalArgumentException(
                    "JwksRenderer at M2.RC1 supports only RS256; got " + key.alg());
        }
        try {
            byte[] pkcs8 = key.material().bytes();
            java.security.interfaces.RSAPrivateCrtKey priv =
                    (java.security.interfaces.RSAPrivateCrtKey) KeyFactory.getInstance("RSA")
                            .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
            RSAKey rsaJwk = new RSAKey.Builder(pub)
                    .keyID(key.kid())
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                    .build();
            Map<String, Object> json = new HashMap<>(rsaJwk.toJSONObject());
            json.remove("kty");
            json.remove("kid");
            json.remove("use");
            json.remove("alg");
            return new JsonWebKey("RSA", key.kid(), "sig", "RS256", json);
        } catch (Exception e) {
            throw new IllegalStateException("failed to render JWK for kid " + key.kid(), e);
        }
    }
}
