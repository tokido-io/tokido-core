package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Outcome of {@code IdentityEngine.authorize}. Framework adapters pattern-match
 * on the variant and translate to the appropriate HTTP response (302 for
 * {@link Redirect}, 400 for {@link Error}, render login UI for
 * {@link LoginRequired}, etc.).
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public sealed interface AuthorizeResult
        permits AuthorizeResult.Redirect,
                AuthorizeResult.Error,
                AuthorizeResult.LoginRequired,
                AuthorizeResult.ConsentRequired,
                AuthorizeResult.MfaRequired {

    /**
     * Redirect the browser to {@code redirectUri} with {@code params} attached
     * (typically as query string for {@code response_mode=query} or fragment
     * for {@code response_mode=fragment}). The adapter chooses based on
     * the request's {@code response_mode}.
     *
     * @param redirectUri target URI; non-null
     * @param params      params to attach; non-null
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Redirect(URI redirectUri, Map<String, String> params) implements AuthorizeResult {
        public Redirect {
            Objects.requireNonNull(redirectUri, "redirectUri");
            params = Map.copyOf(Objects.requireNonNull(params, "params"));
        }
    }

    /**
     * Error response. {@code code} is a wire-format error code (e.g.,
     * {@code "invalid_request"}, {@code "unauthorized_client"}). {@code state}
     * is echoed from the request when present.
     *
     * @param code        wire error code; non-null and non-blank
     * @param description optional human-readable description; nullable
     * @param state       echoed state; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Error(String code, String description, String state) implements AuthorizeResult {
        public Error {
            Objects.requireNonNull(code, "code");
            if (code.isBlank()) {
                throw new IllegalArgumentException("code must not be blank");
            }
        }
    }

    /**
     * End-user authentication is required. The adapter renders the login UI.
     *
     * @param reason optional reason for the prompt; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record LoginRequired(String reason) implements AuthorizeResult {}

    /**
     * End-user consent is required for {@code requestedScopes}.
     *
     * @param requestedScopes scopes that need consent; non-null
     * @param state           echoed state; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record ConsentRequired(Set<String> requestedScopes, String state) implements AuthorizeResult {
        public ConsentRequired {
            requestedScopes = Set.copyOf(Objects.requireNonNull(requestedScopes, "requestedScopes"));
        }
    }

    /**
     * MFA / step-up authentication is required. The {@code requiredAcr}
     * carries the {@code acr} values from the authorize request that the
     * current session does not yet satisfy. The adapter renders an MFA
     * challenge and resumes via a follow-up authorize call (M4).
     *
     * @param requiredAcr ACR values needed; non-null
     * @param state       echoed state; nullable
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record MfaRequired(Set<String> requiredAcr, String state) implements AuthorizeResult {
        public MfaRequired {
            requiredAcr = Set.copyOf(Objects.requireNonNull(requiredAcr, "requiredAcr"));
        }
    }
}
