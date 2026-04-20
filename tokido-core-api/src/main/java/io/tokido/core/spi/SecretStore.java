package io.tokido.core.spi;

import io.tokido.core.StoredSecret;

import java.util.Map;

/**
 * Pluggable secret persistence for the MFA engine.
 *
 * <p>The library never encrypts or decrypts secrets — that is the implementation's
 * responsibility. A production implementation might wrap secrets with KMS envelope
 * encryption, HashiCorp Vault, or a local keystore before persisting.
 *
 * <p>An in-memory implementation for testing is provided in {@code tokido-core-test}.
 *
 * <h2>SecretStore callback sequence</h2>
 *
 * <p>The following documents exactly which methods the engine calls, in what order,
 * for each MFA operation. Use this as the authoritative contract when implementing.
 *
 * <h3>MfaManager.enroll(userId, factorType, ctx)</h3>
 * <ol>
 *   <li>{@link #exists(String, String)} — aborts with {@code AlreadyEnrolledException} if true</li>
 *   <li>Factor provider calls {@link #store(String, String, byte[], Map)} with initial secret
 *       and metadata (e.g., {@code lastCounter}, {@code createdAt}, {@code accountName})</li>
 *   <li>If the factor requires confirmation:
 *       {@link #update(String, String, Map)} with {@code {confirmed: false}} — the engine
 *       owns the confirmation lifecycle; providers do not set this flag</li>
 * </ol>
 *
 * <h3>MfaManager.confirmEnrollment(userId, factorType, credential)</h3>
 * <ol>
 *   <li>{@link #load(String, String)} — reads current state including {@code confirmed} flag</li>
 *   <li>Factor provider verifies the credential internally without persisting verification progress
 *       (e.g. TOTP does not write {@code lastCounter} / {@code lastUsedAt} during this step)</li>
 *   <li>On success: {@link #update(String, String, Map)} with {@code {confirmed: true}}</li>
 *   <li>On failure: no store calls</li>
 * </ol>
 *
 * <h3>MfaManager.verify(userId, factorType, credential)</h3>
 * <ol>
 *   <li>{@link #load(String, String)} — reads current state</li>
 *   <li>If factor requires confirmation and {@code confirmed} is false: returns failure immediately,
 *       no further store calls</li>
 *   <li>Factor provider verifies and — on success only — calls
 *       {@link #update(String, String, Map)} with factor-specific progress keys:
 *       <ul>
 *         <li>TOTP: {@code {lastCounter, lastUsedAt}}</li>
 *         <li>Recovery: {@code {hashedCodes, lastUsedAt}} (consumed code removed from list)</li>
 *       </ul>
 *   </li>
 * </ol>
 *
 * <h3>MfaManager.unenroll(userId, factorType)</h3>
 * <ol>
 *   <li>{@link #exists(String, String)} — aborts with {@code NotEnrolledException} if false</li>
 *   <li>Factor provider performs any internal cleanup (no store calls for built-in factors)</li>
 *   <li>{@link #delete(String, String)}</li>
 * </ol>
 *
 * <h2>update() merge semantics</h2>
 *
 * <p><strong>Implementations MUST treat {@link #update} as a metadata merge — keys absent from
 * the provided map MUST be preserved.</strong> A full metadata replace will corrupt state (e.g.,
 * overwriting {@code accountName} or {@code lastCounter} when only {@code confirmed} is updated).
 *
 * <h2>Metadata keys</h2>
 *
 * <p>All metadata keys written or read by the engine and built-in providers are declared as
 * constants in {@link Metadata}. Use these when building typed storage schemas or inspecting
 * stored records.
 */
public interface SecretStore {

    /**
     * Store a secret and its metadata for a user + factor combination.
     *
     * @param userId     the user identifier
     * @param factorType the factor type (e.g., "totp", "recovery")
     * @param secret     the raw secret bytes (may be empty for factors that don't use a shared secret)
     * @param metadata   factor-specific metadata to persist alongside the secret
     */
    void store(String userId, String factorType, byte[] secret, Map<String, Object> metadata);

    /**
     * Load a stored secret and its metadata.
     *
     * @return the stored secret, or null if not found
     */
    StoredSecret load(String userId, String factorType);

    /**
     * Merge updated metadata into an existing stored secret.
     *
     * <p><strong>Only the provided keys are updated; existing keys not present in the map
     * MUST be preserved.</strong> A full metadata replace is incorrect and will corrupt state.
     *
     * @param userId     the user identifier
     * @param factorType the factor type
     * @param metadata   the metadata entries to merge
     */
    void update(String userId, String factorType, Map<String, Object> metadata);

    /**
     * Delete a stored secret and all its metadata.
     */
    void delete(String userId, String factorType);

    /**
     * Check whether a secret exists for the given user + factor combination.
     */
    boolean exists(String userId, String factorType);

    /**
     * Metadata keys written and read by the engine and built-in factor providers.
     *
     * <p>Use these constants when implementing {@link SecretStore} to build typed storage
     * schemas, attribute mappings, or projection expressions.
     */
    final class Metadata {

        private Metadata() {}

        /**
         * Boolean. Whether the enrollment has been confirmed by the user supplying a valid
         * credential after enrollment. Set to {@code false} by the engine immediately after
         * {@code store()}, and to {@code true} on successful {@code confirmEnrollment()}.
         * Only present for factors where {@code FactorProvider.requiresConfirmation()} is true.
         */
        public static final String CONFIRMED = "confirmed";

        /**
         * Long. The TOTP time-step counter value of the most recently accepted code.
         * Used for replay protection. Set to {@code -1L} on enrollment; updated on each
         * successful verification.
         */
        public static final String LAST_COUNTER = "lastCounter";

        /**
         * Long. Epoch-millisecond timestamp of the most recent successful verification.
         * Set by TOTP and recovery providers on successful verify.
         */
        public static final String LAST_USED_AT = "lastUsedAt";

        /**
         * Long. Epoch-millisecond timestamp when the enrollment was created.
         * Set on initial {@code store()} by the factor provider.
         */
        public static final String CREATED_AT = "createdAt";

        /**
         * String. The account name used to build the {@code otpauth://} URI and QR code
         * during TOTP enrollment. Defaults to the userId if not provided in the enrollment
         * context.
         */
        public static final String ACCOUNT_NAME = "accountName";

        /**
         * List&lt;String&gt;. bcrypt-hashed recovery codes. Each entry is consumed (removed)
         * on a successful recovery code verification.
         */
        public static final String HASHED_CODES = "hashedCodes";
    }
}
