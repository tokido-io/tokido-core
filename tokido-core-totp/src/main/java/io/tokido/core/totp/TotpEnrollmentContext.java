package io.tokido.core.totp;

import io.tokido.core.EnrollmentContext;
import io.tokido.core.spi.SecretStore;

import java.util.Objects;

/**
 * Type-safe enrollment input for {@link TotpFactorProvider}.
 * <p>
 * Prefer this over raw {@link EnrollmentContext#of(String, Object)} so the account name for the
 * otpauth URI is required at compile time and cannot be mistyped or omitted.
 */
public record TotpEnrollmentContext(String accountName) {

    public TotpEnrollmentContext {
        Objects.requireNonNull(accountName, "accountName");
    }

    public EnrollmentContext asEnrollmentContext() {
        return EnrollmentContext.of(SecretStore.Metadata.ACCOUNT_NAME, accountName);
    }
}

