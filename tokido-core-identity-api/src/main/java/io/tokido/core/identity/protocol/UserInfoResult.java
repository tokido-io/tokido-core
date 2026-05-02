package io.tokido.core.identity.protocol;

import io.tokido.core.identity.spi.UserClaim;
import org.apiguardian.api.API;

import java.util.Objects;
import java.util.Set;

/** Outcome of {@code IdentityEngine.userInfo}. */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public sealed interface UserInfoResult permits UserInfoResult.Success, UserInfoResult.Error {

    /**
     * Successful userinfo response (OIDC Core §5.3.2).
     *
     * @param subjectId the {@code sub} claim; non-null
     * @param claims    claims emitted; non-null
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Success(String subjectId, Set<UserClaim> claims) implements UserInfoResult {
        public Success {
            Objects.requireNonNull(subjectId, "subjectId");
            claims = Set.copyOf(Objects.requireNonNull(claims, "claims"));
        }
    }

    /**
     * Error response.
     *
     * @param code        wire error code; non-null
     * @param description optional human-readable description; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Error(String code, String description) implements UserInfoResult {
        public Error { Objects.requireNonNull(code, "code"); }
    }
}
