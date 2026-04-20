package io.tokido.core.totp;

import io.tokido.core.*;
import io.tokido.core.spi.FactorProvider;
import io.tokido.core.spi.SecretStore;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * TOTP (Time-based One-Time Password) factor provider.
 * Implements RFC 6238 with replay protection, configurable time window,
 * and GraalVM-safe QR code generation.
 *
 * <p>By default this provider requires confirmation: after {@code MfaManager.enroll()}, the user must
 * call {@code MfaManager.confirmEnrollment()} with a valid TOTP code before the factor
 * becomes active for verification.
 * Use {@link TotpConfig#requiresConfirmation(boolean)} with {@code false} for server-side
 * provisioning flows where the factor should be active immediately.
 *
 * <h2>Metadata written to SecretStore</h2>
 * <ul>
 *   <li>{@link SecretStore.Metadata#LAST_COUNTER} — set to {@code -1L} on enrollment;
 *       updated to the accepted counter on each successful {@code MfaManager#verify} (not when
 *       validating during {@code MfaManager#confirmEnrollment}, which checks the code without
 *       advancing replay state)</li>
 *   <li>{@link SecretStore.Metadata#CREATED_AT} — epoch-millisecond timestamp of enrollment</li>
 *   <li>{@link SecretStore.Metadata#ACCOUNT_NAME} — account name used in the otpauth URI;
 *       defaults to userId if not provided in the enrollment context</li>
 *   <li>{@link SecretStore.Metadata#LAST_USED_AT} — epoch-millisecond timestamp of the most
 *       recent successful verification; absent until first use</li>
 * </ul>
 *
 * <p>Note: the {@link SecretStore.Metadata#CONFIRMED} flag is managed exclusively by the
 * engine ({@code MfaManager}) and is never set by this provider.
 *
 * <p>Runtime dependency: {@code com.google.zxing:core} (lazily loaded on first enrollment).
 */
public class TotpFactorProvider implements FactorProvider<TotpEnrollmentResult, TotpVerificationResult> {

    private final TotpConfig config;
    private final SecretStore secretStore;

    public TotpFactorProvider(TotpConfig config, SecretStore secretStore) {
        this.config = config;
        this.secretStore = secretStore;
    }

    public TotpFactorProvider(SecretStore secretStore) {
        this(TotpConfig.defaults(), secretStore);
    }

    @Override
    public String factorType() {
        return "totp";
    }

    @Override
    public boolean requiresConfirmation() {
        return config.requiresConfirmation();
    }

    @Override
    public TotpEnrollmentResult enroll(String userId, EnrollmentContext ctx) {
        byte[] secret = new byte[config.secretLength()];
        new SecureRandom().nextBytes(secret);

        String base32Secret = Base32.encode(secret);
        String accountName = resolveAccountName(userId, ctx);
        String secretUri = "otpauth://totp/" + urlEncode(accountName)
                + "?secret=" + base32Secret
                + "&issuer=" + urlEncode(config.issuer());

        String qrCodeBase64;
        try {
            qrCodeBase64 = QrCodeGenerator.toPngBase64(secretUri);
        } catch (RuntimeException e) {
            qrCodeBase64 = "";
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put(SecretStore.Metadata.LAST_COUNTER, -1L);
        metadata.put(SecretStore.Metadata.CREATED_AT, System.currentTimeMillis());
        metadata.put(SecretStore.Metadata.ACCOUNT_NAME, accountName);
        // Note: CONFIRMED is not set here — the engine sets it after store() returns.

        secretStore.store(userId, factorType(), secret, metadata);

        return new TotpEnrollmentResult(secretUri, qrCodeBase64);
    }

    @Override
    public TotpVerificationResult verify(String userId, String credential, VerificationContext ctx) {
        StoredSecret stored = secretStore.load(userId, factorType());
        if (stored == null) {
            throw new NotEnrolledException(userId, factorType());
        }

        int inputCode;
        try {
            inputCode = Integer.parseInt(credential.trim());
        } catch (NumberFormatException e) {
            return new TotpVerificationResult(false, "invalid");
        }

        byte[] secret = stored.secret();
        long lastCounter = ((Number) stored.metadata().getOrDefault(SecretStore.Metadata.LAST_COUNTER, -1L)).longValue();
        long currentCounter = System.currentTimeMillis() / 1000L / config.timeStepSeconds();

        for (long c = currentCounter - config.windowSize(); c <= currentCounter + config.windowSize(); c++) {
            int expected = TotpAlgorithm.generate(secret, c, config);
            if (expected == inputCode) {
                if (c <= lastCounter) {
                    return new TotpVerificationResult(false, "replay");
                }
                if (VerificationContext.shouldPersistVerificationProgress(ctx)) {
                    secretStore.update(userId, factorType(), Map.of(
                            SecretStore.Metadata.LAST_COUNTER, c,
                            SecretStore.Metadata.LAST_USED_AT, System.currentTimeMillis()
                    ));
                }
                return new TotpVerificationResult(true, null);
            }
        }
        return new TotpVerificationResult(false, "invalid");
    }

    @Override
    public void unenroll(String userId) {
        // No external cleanup needed — SecretStore.delete() is called by the engine
    }

    @Override
    public FactorStatus status(String userId) {
        StoredSecret stored = secretStore.load(userId, factorType());
        if (stored == null) {
            return FactorStatus.notEnrolled();
        }
        boolean confirmed;
        if (!requiresConfirmation()) {
            confirmed = true;
        } else {
            Boolean c = (Boolean) stored.metadata().get(SecretStore.Metadata.CONFIRMED);
            confirmed = c != null && c;
        }
        Map<String, Object> attrs = new HashMap<>();
        attrs.put(SecretStore.Metadata.CREATED_AT, stored.metadata().get(SecretStore.Metadata.CREATED_AT));
        Object lastUsedAt = stored.metadata().get(SecretStore.Metadata.LAST_USED_AT);
        if (lastUsedAt != null) {
            attrs.put(SecretStore.Metadata.LAST_USED_AT, lastUsedAt);
        }
        Object accountName = stored.metadata().get(SecretStore.Metadata.ACCOUNT_NAME);
        if (accountName != null) {
            attrs.put(SecretStore.Metadata.ACCOUNT_NAME, accountName);
        }
        return new FactorStatus(true, confirmed, Map.copyOf(attrs));
    }

    private static String resolveAccountName(String userId, EnrollmentContext ctx) {
        Object v = ctx.properties().get(SecretStore.Metadata.ACCOUNT_NAME);
        if (v instanceof String s) {
            return s;
        }
        // Backward compatibility with the pre-Metadata constant usage.
        Object legacy = ctx.properties().get("accountName");
        if (legacy instanceof String s) {
            return s;
        }
        return userId;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
