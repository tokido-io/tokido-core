package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.util.Objects;

/** Outcome of {@code IdentityEngine.revoke} (RFC 7009). */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public sealed interface RevocationResult permits RevocationResult.Revoked, RevocationResult.Error {

    /** Per RFC 7009 §2.2, a successful revocation always responds 200 — even for unknown tokens. */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Revoked() implements RevocationResult {}

    /**
     * Error response.
     *
     * @param code        wire error code; non-null
     * @param description optional description; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Error(String code, String description) implements RevocationResult {
        public Error { Objects.requireNonNull(code, "code"); }
    }
}
