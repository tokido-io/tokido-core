package io.tokido.core.totp;

import java.util.Objects;

/**
 * Type-safe enrollment input for {@link TotpFactorProvider}.
 * <p>
 * Prefer this over raw stringly-typed enrollment maps so the account name for the
 * otpauth URI is required at compile time and cannot be mistyped or omitted.
 */
public record TotpEnrollmentContext(String accountName) {

    public TotpEnrollmentContext {
        Objects.requireNonNull(accountName, "accountName");
    }
}

