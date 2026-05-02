package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * A user's consent grant for a (subjectId, clientId, scopes) tuple.
 * Consents are typically created when the user clicks "allow" on the
 * consent screen and are looked up on subsequent authorize calls so the
 * user is not re-prompted.
 *
 * @param subjectId  subject of the consent; non-null and non-blank
 * @param clientId   client the consent applies to; non-null and non-blank
 * @param scopes     scopes consented to
 * @param expiration when the consent expires
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record Consent(String subjectId, String clientId, Set<String> scopes, Instant expiration) {

    public Consent {
        Objects.requireNonNull(subjectId, "subjectId");
        if (subjectId.isBlank()) {
            throw new IllegalArgumentException("subjectId must not be blank");
        }
        Objects.requireNonNull(clientId, "clientId");
        if (clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
        Objects.requireNonNull(expiration, "expiration");
    }
}
