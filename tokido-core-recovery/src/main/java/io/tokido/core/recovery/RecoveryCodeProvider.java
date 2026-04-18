package io.tokido.core.recovery;

import io.tokido.core.*;
import io.tokido.core.spi.FactorProvider;
import io.tokido.core.spi.SecretStore;
import org.mindrot.jbcrypt.BCrypt;

import java.security.SecureRandom;
import java.util.*;

/**
 * Recovery code factor provider. Generates single-use backup codes
 * with bcrypt hashing for safe storage.
 * <p>
 * Runtime dependency: {@code org.mindrot:jbcrypt} (lazily loaded on first enrollment).
 */
public class RecoveryCodeProvider implements FactorProvider<RecoveryEnrollmentResult, RecoveryVerificationResult> {

    private final RecoveryConfig config;
    private final SecretStore secretStore;

    public RecoveryCodeProvider(RecoveryConfig config, SecretStore secretStore) {
        this.config = config;
        this.secretStore = secretStore;
    }

    public RecoveryCodeProvider(SecretStore secretStore) {
        this(RecoveryConfig.defaults(), secretStore);
    }

    @Override
    public String factorType() {
        return "recovery";
    }

    @Override
    public boolean requiresConfirmation() {
        return false;
    }

    @Override
    public RecoveryEnrollmentResult enroll(String userId, EnrollmentContext ctx) {
        SecureRandom rng = new SecureRandom();
        String format = "%0" + config.codeLength() + "d";
        int bound = 1;
        for (int i = 0; i < config.codeLength(); i++) {
            bound *= 10;
        }

        List<String> plainCodes = new ArrayList<>(config.codeCount());
        List<String> hashedCodes = new ArrayList<>(config.codeCount());
        for (int i = 0; i < config.codeCount(); i++) {
            String code = String.format(format, rng.nextInt(bound));
            plainCodes.add(code);
            hashedCodes.add(BCrypt.hashpw(code, BCrypt.gensalt(config.bcryptCost())));
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("hashedCodes", hashedCodes);
        metadata.put("createdAt", System.currentTimeMillis());

        secretStore.store(userId, factorType(), new byte[0], metadata);

        return new RecoveryEnrollmentResult(List.copyOf(plainCodes));
    }

    @Override
    @SuppressWarnings("unchecked")
    public RecoveryVerificationResult verify(String userId, String credential, VerificationContext ctx) {
        StoredSecret stored = secretStore.load(userId, factorType());
        if (stored == null) {
            throw new NotEnrolledException(userId, factorType());
        }

        List<String> hashedCodes = new ArrayList<>((List<String>) stored.metadata().get("hashedCodes"));

        for (int i = 0; i < hashedCodes.size(); i++) {
            if (BCrypt.checkpw(credential, hashedCodes.get(i))) {
                hashedCodes.remove(i);
                secretStore.update(userId, factorType(), Map.of(
                        "hashedCodes", hashedCodes,
                        "lastUsedAt", System.currentTimeMillis()
                ));
                return new RecoveryVerificationResult(true, hashedCodes.size());
            }
        }
        return new RecoveryVerificationResult(false, hashedCodes.size());
    }

    @Override
    public void unenroll(String userId) {
        // No external cleanup — SecretStore.delete() called by engine
    }

    @Override
    @SuppressWarnings("unchecked")
    public FactorStatus status(String userId) {
        StoredSecret stored = secretStore.load(userId, factorType());
        if (stored == null) {
            return FactorStatus.notEnrolled();
        }
        List<String> hashedCodes = (List<String>) stored.metadata().getOrDefault("hashedCodes", List.of());
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("codesRemaining", hashedCodes.size());
        attrs.put("createdAt", stored.metadata().get("createdAt"));
        Object lastUsedAt = stored.metadata().get("lastUsedAt");
        if (lastUsedAt != null) {
            attrs.put("lastUsedAt", lastUsedAt);
        }
        return new FactorStatus(true, true, Map.copyOf(attrs));
    }
}
