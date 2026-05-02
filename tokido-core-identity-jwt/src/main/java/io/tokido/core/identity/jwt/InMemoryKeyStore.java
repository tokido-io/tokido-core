package io.tokido.core.identity.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.tokido.core.identity.key.KeyMaterial;
import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import org.apiguardian.api.API;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

/**
 * Convenience {@link KeyStore} that generates a fresh RS256 keypair on
 * construction. Intended for development and tests; production deployments
 * should use a proper {@code KeyStore} backed by an HSM, KMS, or persisted
 * key material.
 *
 * <p>The generated key has a randomly-chosen {@code kid} (UUID), state
 * {@link KeyState#ACTIVE}, {@code notBefore} = now, {@code notAfter} = now + 365 days.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class InMemoryKeyStore implements KeyStore {

    private final SigningKey active;

    public InMemoryKeyStore() {
        try {
            String kid = UUID.randomUUID().toString();
            RSAKey rsaJwk = new RSAKeyGenerator(2048)
                    .keyID(kid)
                    .algorithm(JWSAlgorithm.RS256)
                    .generate();
            byte[] pkcs8 = rsaJwk.toRSAPrivateKey().getEncoded();
            Instant now = Instant.now();
            this.active = new SigningKey(
                    kid,
                    SignatureAlgorithm.RS256,
                    new KeyMaterial(pkcs8, SignatureAlgorithm.RS256),
                    KeyState.ACTIVE,
                    now,
                    now.plus(365, ChronoUnit.DAYS));
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate RSA keypair", e);
        }
    }

    @Override
    public SigningKey activeSigningKey(SignatureAlgorithm alg) {
        if (alg != SignatureAlgorithm.RS256) {
            throw new IllegalStateException(
                    "InMemoryKeyStore only knows RS256; got " + alg);
        }
        return active;
    }

    @Override
    public Set<SigningKey> allKeys() {
        return Set.of(active);
    }
}
