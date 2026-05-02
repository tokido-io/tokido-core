package io.tokido.core.identity.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.tokido.core.identity.engine.TokenSigner;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import org.apiguardian.api.API;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Nimbus JOSE+JWT-backed {@link TokenSigner}.
 *
 * <p>Signs the supplied payload with the supplied {@link SigningKey} and
 * returns a compact-serialization JWS. Sets the {@code kid} header from
 * the key. Refuses to sign with a {@link KeyState#RETIRED} key
 * (per ADR-0007).
 *
 * <p>Supported algorithms: {@link SignatureAlgorithm#RS256},
 * {@link SignatureAlgorithm#ES256}, {@link SignatureAlgorithm#EDDSA} (Ed25519).
 *
 * <p>Key material interpretation:
 * <ul>
 *   <li>RS256 / ES256: PKCS#8-encoded DER bytes</li>
 *   <li>EdDSA: OctetKeyPair JSON serialization (UTF-8)</li>
 * </ul>
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class NimbusTokenSigner implements TokenSigner {

    @Override
    public String sign(String payload, SigningKey key) {
        if (key.state() == KeyState.RETIRED) {
            throw new IllegalStateException(
                    "key " + key.kid() + " is RETIRED; new signatures must use an ACTIVE key");
        }
        try {
            JWSAlgorithm alg = nimbusAlg(key.alg());
            JWSSigner signer = nimbusSigner(key);
            JWSHeader header = new JWSHeader.Builder(alg).keyID(key.kid()).build();
            JWSObject jws = new JWSObject(header, new Payload(payload));
            jws.sign(signer);
            return jws.serialize();
        } catch (JOSEException | java.security.GeneralSecurityException | java.text.ParseException e) {
            throw new IllegalStateException("failed to sign with key " + key.kid(), e);
        }
    }

    private static JWSAlgorithm nimbusAlg(SignatureAlgorithm a) {
        return switch (a) {
            case RS256 -> JWSAlgorithm.RS256;
            case ES256 -> JWSAlgorithm.ES256;
            case EDDSA -> JWSAlgorithm.EdDSA;
        };
    }

    private static JWSSigner nimbusSigner(SigningKey key) throws java.security.GeneralSecurityException, JOSEException, java.text.ParseException {
        byte[] bytes = key.material().bytes();
        return switch (key.alg()) {
            case RS256 -> {
                RSAPrivateKey priv = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(bytes));
                yield new RSASSASigner(priv);
            }
            case ES256 -> {
                ECPrivateKey priv = (ECPrivateKey) KeyFactory.getInstance("EC")
                        .generatePrivate(new PKCS8EncodedKeySpec(bytes));
                yield new ECDSASigner(priv);
            }
            case EDDSA -> {
                OctetKeyPair okp = OctetKeyPair.parse(new String(bytes, StandardCharsets.UTF_8));
                yield new Ed25519Signer(okp);
            }
        };
    }
}
