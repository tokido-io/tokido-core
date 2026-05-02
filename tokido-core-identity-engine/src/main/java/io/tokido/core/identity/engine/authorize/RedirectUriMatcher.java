package io.tokido.core.identity.engine.authorize;

import java.util.Set;

/**
 * Exact-match redirect URI lookup per RFC 6749 §3.1.2.3 + OIDC Core §3.1.2.1.
 * No URL normalization; consumers must register URIs in the exact form clients
 * send.
 */
final class RedirectUriMatcher {

    private RedirectUriMatcher() {}

    /**
     * @param submitted    the redirect_uri parameter from the authorize request; nullable
     * @param registered   the set of redirect URIs registered for the client
     * @return true iff {@code submitted} is non-null and present in {@code registered}
     */
    static boolean matches(String submitted, Set<String> registered) {
        return submitted != null && registered.contains(submitted);
    }
}
