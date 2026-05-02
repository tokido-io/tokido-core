package io.tokido.core.identity.key;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Objects;

/**
 * A signing key with full lifecycle metadata.
 *
 * @param kid       JWS key id, non-null and non-blank
 * @param alg       algorithm, must match {@code material.alg()}
 * @param material  key bytes
 * @param state     {@link KeyState#ACTIVE} for the current signing key,
 *                  {@link KeyState#RETIRED} for keys still in JWKS for verification
 * @param notBefore start of validity (inclusive)
 * @param notAfter  end of validity (exclusive); must be after {@code notBefore}
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record SigningKey(String kid,
                         SignatureAlgorithm alg,
                         KeyMaterial material,
                         KeyState state,
                         Instant notBefore,
                         Instant notAfter) {

    public SigningKey {
        Objects.requireNonNull(kid, "kid");
        if (kid.isBlank()) {
            throw new IllegalArgumentException("kid must not be blank");
        }
        Objects.requireNonNull(alg, "alg");
        Objects.requireNonNull(material, "material");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        if (alg != material.alg()) {
            throw new IllegalArgumentException(
                    "key alg " + alg + " does not match material alg " + material.alg());
        }
        if (!notAfter.isAfter(notBefore)) {
            throw new IllegalArgumentException(
                    "notAfter (" + notAfter + ") must be after notBefore (" + notBefore + ")");
        }
    }
}
