package io.tokido.core.identity.engine;

import io.tokido.core.identity.key.KeyStore;
import org.apiguardian.api.API;

import java.util.Map;

/**
 * SPI for verifying compact-serialization JWS tokens. Mirrors
 * {@link TokenSigner} on the verification side: implementations parse the
 * compact JWS, look up the matching {@link io.tokido.core.identity.key.SigningKey}
 * (active or retired) by {@code kid} from the supplied {@link KeyStore},
 * verify the signature, and check the {@code exp} / {@code nbf} temporal
 * claims if present.
 *
 * <p>Implemented by {@code NimbusTokenVerifier} in
 * {@code tokido-core-identity-jwt} (M2.RC1). The engine module never directly
 * imports any JWT library — it talks to this SPI.
 *
 * <p>Failure mode: implementations return an <strong>empty map</strong> when
 * verification fails for any reason (malformed token, missing/unknown
 * {@code kid}, bad signature, expired/not-yet-valid token). Callers
 * distinguish a valid token from an invalid one by checking whether the
 * returned map is empty. Implementations must not throw.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2.RC1")
public interface TokenVerifier {

    /**
     * Parse, locate the verification key, and verify the supplied compact JWS.
     *
     * @param compactJws compact-serialization JWS string ({@code header.payload.signature})
     * @param keyStore   the engine's key store; the implementation picks a
     *                   matching key by {@code kid}. Both ACTIVE and RETIRED
     *                   keys are valid for verification (per ADR-0007).
     * @return parsed JWS claims as a {@code Map<String, Object>}; or an empty
     *         map if verification fails for any reason
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M2.RC1")
    Map<String, Object> verify(String compactJws, KeyStore keyStore);
}
