package io.tokido.core.totp;

import io.tokido.core.EnrollmentContext;
import io.tokido.core.spi.SecretStore;

import java.util.Objects;

/**
 * Boundary helpers for converting typed TOTP enrollment inputs into the SPI {@link EnrollmentContext}.
 */
public final class TotpEnrollmentContexts {

    private TotpEnrollmentContexts() {}

    public static EnrollmentContext enrollment(String accountName) {
        Objects.requireNonNull(accountName, "accountName");
        return EnrollmentContext.of(SecretStore.Metadata.ACCOUNT_NAME, accountName);
    }

    public static EnrollmentContext enrollment(TotpEnrollmentContext ctx) {
        Objects.requireNonNull(ctx, "ctx");
        return enrollment(ctx.accountName());
    }
}

