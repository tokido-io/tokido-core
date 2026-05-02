package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * A server-side persisted artifact backing one of the OAuth/OIDC token-like
 * objects: authorization codes, refresh tokens, opaque reference access tokens,
 * and stored consents.
 *
 * <p>The {@code handle} is the opaque server-side identifier; the
 * implementation maps it to retrieve the grant. The {@code data} field is
 * an opaque serialized payload — the engine writes a self-describing string
 * (typically JSON), the store treats it as an opaque blob.
 *
 * @param handle       opaque server-side identifier; non-null and non-blank
 * @param type         grant type
 * @param subjectId    subject this grant belongs to
 * @param clientId     client this grant was issued to
 * @param scopes       scopes granted
 * @param creationTime when the grant was created
 * @param expiration   when the grant expires
 * @param consumedTime when the grant was consumed (one-time-use); {@code null} if not yet consumed
 * @param data         opaque serialized payload; non-null
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record PersistedGrant(
        String handle,
        GrantType type,
        String subjectId,
        String clientId,
        Set<String> scopes,
        Instant creationTime,
        Instant expiration,
        Instant consumedTime,
        String data) {

    public PersistedGrant {
        Objects.requireNonNull(handle, "handle");
        if (handle.isBlank()) {
            throw new IllegalArgumentException("handle must not be blank");
        }
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(clientId, "clientId");
        scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
        Objects.requireNonNull(creationTime, "creationTime");
        Objects.requireNonNull(expiration, "expiration");
        // consumedTime is intentionally nullable
        Objects.requireNonNull(data, "data");
    }
}
