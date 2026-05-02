package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * The framework adapter's representation of "who the browser session says
 * is logged in". The engine reads this on every authorize call to decide
 * whether to short-circuit, prompt for login, or require step-up.
 *
 * @param subjectId       authenticated user's subject id; {@code null} for anonymous
 * @param authenticatedAt when the session was authenticated; {@code null} for anonymous
 * @param amr             AMR values satisfied so far ({@code "pwd"}, {@code "otp"}, ...); null becomes empty
 * @param acr             current ACR satisfied; {@code null} if no ACR has been pinned
 * @param session         opaque session attributes the adapter wishes to round-trip; null becomes empty
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record AuthenticationState(
        String subjectId,
        Instant authenticatedAt,
        Set<String> amr,
        String acr,
        Map<String, String> session) {

    public AuthenticationState {
        amr = amr == null ? Set.of() : Set.copyOf(amr);
        session = session == null ? Map.of() : Map.copyOf(session);
    }

    /**
     * Sentinel for unauthenticated requests.
     *
     * @return an AuthenticationState with all nulls and empty collections
     */
    public static AuthenticationState anonymous() {
        return new AuthenticationState(null, null, Set.of(), null, Map.of());
    }
}
