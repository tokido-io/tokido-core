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
 *
 * <p>This provider does not require confirmation — codes are active immediately after enrollment.
 *
 * <h2>Metadata written to SecretStore</h2>
 * <ul>
 *   <li>{@link SecretStore.Metadata#HASHED_CODES} — {@code List<String>} of bcrypt-hashed codes;
 *       each successful verification removes the matched code from the list</li>
 *   <li>{@link SecretStore.Metadata#CREATED_AT} — epoch-millisecond timestamp of enrollment</li>
 *   <li>{@link SecretStore.Metadata#LAST_USED_AT} — epoch-millisecond timestamp of the most
 *       recent successful verification; absent until first use</li>
 * </ul>
 *
 * <p>Runtime dependency: {@code org.mindrot:jbcrypt} (lazily loaded on first enrollment).
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
        metadata.put(SecretStore.Metadata.HASHED_CODES, hashedCodes);
        metadata.put(SecretStore.Metadata.CREATED_AT, System.currentTimeMillis());

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

        List<String> hashedCodes = new ArrayList<>((List<String>) stored.metadata().get(SecretStore.Metadata.HASHED_CODES));

        for (int i = 0; i < hashedCodes.size(); i++) {
            if (BCrypt.checkpw(credential, hashedCodes.get(i))) {
                hashedCodes.remove(i);
                secretStore.update(userId, factorType(), Map.of(
                        SecretStore.Metadata.HASHED_CODES, hashedCodes,
                        SecretStore.Metadata.LAST_USED_AT, System.currentTimeMillis()
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
        List<String> hashedCodes = (List<String>) stored.metadata().getOrDefault(SecretStore.Metadata.HASHED_CODES, List.of());
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("codesRemaining", hashedCodes.size());
        attrs.put(SecretStore.Metadata.CREATED_AT, stored.metadata().get(SecretStore.Metadata.CREATED_AT));
        Object lastUsedAt = stored.metadata().get(SecretStore.Metadata.LAST_USED_AT);
        if (lastUsedAt != null) {
            attrs.put(SecretStore.Metadata.LAST_USED_AT, lastUsedAt);
        }
        return new FactorStatus(true, true, Map.copyOf(attrs));
    }
}
