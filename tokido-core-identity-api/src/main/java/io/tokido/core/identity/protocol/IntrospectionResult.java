package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Outcome of {@code IdentityEngine.introspect} (RFC 7662). */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public sealed interface IntrospectionResult permits IntrospectionResult.Active, IntrospectionResult.Inactive {

    /**
     * The token is active. RFC 7662 §2.2 — full claim set returned.
     *
     * @param subjectId        subject of the token
     * @param clientId         client the token was issued to
     * @param scope            granted scopes
     * @param exp              expiration time
     * @param iat              issued-at time
     * @param additionalClaims any additional claims to surface; non-null
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Active(String subjectId,
                  String clientId,
                  Set<String> scope,
                  Instant exp,
                  Instant iat,
                  Map<String, Object> additionalClaims) implements IntrospectionResult {
        public Active {
            Objects.requireNonNull(subjectId, "subjectId");
            Objects.requireNonNull(clientId, "clientId");
            scope = Set.copyOf(Objects.requireNonNull(scope, "scope"));
            additionalClaims = Map.copyOf(Objects.requireNonNull(additionalClaims, "additionalClaims"));
        }
    }

    /** Per RFC 7662, an inactive token is reported as {@code active: false} only. */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Inactive() implements IntrospectionResult {}
}
