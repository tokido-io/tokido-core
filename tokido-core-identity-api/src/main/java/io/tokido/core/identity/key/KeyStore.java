package io.tokido.core.identity.key;

import org.apiguardian.api.API;

import java.util.Set;

/**
 * Source of signing keys for the engine.
 *
 * <p>Implementations may serve keys from in-memory collections, an HSM,
 * a cloud KMS, or a database. The engine treats this SPI as read-only
 * during normal request processing; key rotation is an admin op that
 * is not part of the M1 lock (lands at M2 with {@code KeyRotationPolicy}
 * per ADR-0007).
 *
 * <p>Thread-safety: implementations must be safe for concurrent reads
 * across many request threads.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface KeyStore {

    /**
     * Return the active signing key for the given algorithm.
     *
     * @param alg algorithm requested by the engine
     * @return active key; never null
     * @throws IllegalStateException if no active key exists for the algorithm
     */
    SigningKey activeSigningKey(SignatureAlgorithm alg);

    /**
     * Return every key the store knows about (active and retired).
     * Used by the JWKS endpoint to publish the verification key set.
     *
     * @return non-null, possibly empty, immutable set
     */
    Set<SigningKey> allKeys();
}
