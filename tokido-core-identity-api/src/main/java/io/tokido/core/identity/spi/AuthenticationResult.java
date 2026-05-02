package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

/**
 * Outcome of a {@link UserStore#authenticate(String, String)} call.
 * Implementations must return one of the four permitted variants.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public sealed interface AuthenticationResult
        permits AuthenticationResult.Success,
                AuthenticationResult.InvalidCredentials,
                AuthenticationResult.AccountLocked,
                AuthenticationResult.AccountDisabled {

    /**
     * Authentication succeeded; the returned user is the authenticated account.
     *
     * @param user the authenticated user; non-null
     */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record Success(User user) implements AuthenticationResult {
        public Success {
            java.util.Objects.requireNonNull(user, "user");
        }
    }

    /** Username or password did not match any known account. */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record InvalidCredentials() implements AuthenticationResult {}

    /** Account exists but is temporarily locked (e.g., too many failed attempts). */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record AccountLocked() implements AuthenticationResult {}

    /** Account exists but is administratively disabled. */
    @API(status = API.Status.STABLE, since = "0.1.0-M1")
    record AccountDisabled() implements AuthenticationResult {}
}
