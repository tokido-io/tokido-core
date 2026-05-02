package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.net.URI;
import java.util.Map;
import java.util.Objects;

/** Outcome of {@code IdentityEngine.endSession}. */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public sealed interface EndSessionResult permits EndSessionResult.Redirect, EndSessionResult.Done, EndSessionResult.Error {

    /**
     * Redirect the browser back to the post-logout URI.
     *
     * @param redirectUri post-logout redirect target; non-null
     * @param params      params to attach; non-null
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Redirect(URI redirectUri, Map<String, String> params) implements EndSessionResult {
        public Redirect {
            Objects.requireNonNull(redirectUri, "redirectUri");
            params = Map.copyOf(Objects.requireNonNull(params, "params"));
        }
    }

    /** Logout completed; no redirect. The adapter should render a confirmation page. */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Done() implements EndSessionResult {}

    /**
     * Error response.
     *
     * @param code        wire error code; non-null
     * @param description optional description; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Error(String code, String description) implements EndSessionResult {
        public Error { Objects.requireNonNull(code, "code"); }
    }
}
