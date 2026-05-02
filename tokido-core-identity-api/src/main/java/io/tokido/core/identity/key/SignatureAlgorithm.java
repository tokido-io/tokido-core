package io.tokido.core.identity.key;

import org.apiguardian.api.API;

/**
 * JWS signature algorithms supported by the engine, named per RFC 7518.
 * The wire-protocol value matches the enum name.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public enum SignatureAlgorithm {
    /** RFC 7518 — RSASSA-PKCS1-v1_5 using SHA-256. */
    RS256,
    /** RFC 7518 — ECDSA using P-256 and SHA-256. */
    ES256,
    /** RFC 8037 — Edwards-curve Digital Signature Algorithm (Ed25519). */
    EDDSA
}
