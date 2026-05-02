package io.tokido.core.identity.key;

import org.apiguardian.api.API;

import java.util.Objects;

/**
 * Opaque signing-key material — typically a serialized PEM, JWK, or HSM handle —
 * paired with the algorithm it can sign with. The {@code bytes} array is the
 * caller's responsibility to keep confidential; this record does not copy or
 * scrub it.
 *
 * @param bytes raw key material; non-null
 * @param alg   algorithm this material is intended for; non-null
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record KeyMaterial(byte[] bytes, SignatureAlgorithm alg) {

    public KeyMaterial {
        Objects.requireNonNull(bytes, "bytes");
        Objects.requireNonNull(alg, "alg");
    }
}
