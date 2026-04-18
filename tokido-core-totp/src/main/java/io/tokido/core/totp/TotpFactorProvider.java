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
 * <p>
 * Runtime dependency: {@code com.google.zxing:core} (lazily loaded on first enrollment).
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
        return true;
    }

    @Override
    public TotpEnrollmentResult enroll(String userId, EnrollmentContext ctx) {
        byte[] secret = new byte[config.secretLength()];
        new SecureRandom().nextBytes(secret);

        String base32Secret = Base32.encode(secret);
        String accountName = (String) ctx.properties().getOrDefault("accountName", userId);
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
        metadata.put("lastCounter", -1L);
        metadata.put("confirmed", false);
        metadata.put("createdAt", System.currentTimeMillis());

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
        long lastCounter = ((Number) stored.metadata().getOrDefault("lastCounter", -1L)).longValue();
        long currentCounter = System.currentTimeMillis() / 1000L / config.timeStepSeconds();

        for (long c = currentCounter - config.windowSize(); c <= currentCounter + config.windowSize(); c++) {
            int expected = TotpAlgorithm.generate(secret, c, config);
            if (expected == inputCode) {
                if (c <= lastCounter) {
                    return new TotpVerificationResult(false, "replay");
                }
                secretStore.update(userId, factorType(), Map.of(
                        "lastCounter", c,
                        "lastUsedAt", System.currentTimeMillis()
                ));
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
        Boolean confirmed = (Boolean) stored.metadata().getOrDefault("confirmed", true);
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("createdAt", stored.metadata().get("createdAt"));
        Object lastUsedAt = stored.metadata().get("lastUsedAt");
        if (lastUsedAt != null) {
            attrs.put("lastUsedAt", lastUsedAt);
        }
        return new FactorStatus(true, confirmed, Map.copyOf(attrs));
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
