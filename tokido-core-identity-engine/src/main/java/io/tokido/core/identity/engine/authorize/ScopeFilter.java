package io.tokido.core.identity.engine.authorize;

import java.util.Set;

/**
 * Scope validation. Returns the requested scope set if every scope is allowed
 * for the client; throws {@link UnsupportedScopeException} otherwise. Engine
 * surfaces this as the OAuth 2.0 {@code invalid_scope} error.
 */
final class ScopeFilter {

    private ScopeFilter() {}

    /**
     * @param requested scopes from the authorize/token request
     * @param allowed   scopes registered for the client
     * @return {@code requested} (the SET — for chaining); throws if any element is not in {@code allowed}
     */
    static Set<String> filter(Set<String> requested, Set<String> allowed) {
        for (String s : requested) {
            if (!allowed.contains(s)) {
                throw new UnsupportedScopeException(s);
            }
        }
        return requested;
    }

    /** Thrown when a requested scope is not in the client's allowed set. */
    static final class UnsupportedScopeException extends RuntimeException {
        private final String scope;

        UnsupportedScopeException(String scope) {
            super("scope not allowed: " + scope);
            this.scope = scope;
        }

        String scope() { return scope; }
    }
}
