package io.tokido.core.identity.engine.token;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Cryptographically random opaque-handle generator.
 *
 * <p>Used by {@link TokenHandler} to mint refresh-token handles and JWT
 * access-token {@code jti} values. The output is URL-safe Base64 with no
 * padding so the handle can be embedded in URLs / headers without further
 * escaping. Backing entropy is a single static {@link SecureRandom}, which
 * matches the pattern in {@code AuthorizeHandler}.
 */
final class RandomHandle {

    private static final SecureRandom RNG = new SecureRandom();

    private RandomHandle() {}

    /**
     * Produce a fresh handle.
     *
     * @param byteCount number of random bytes; must be positive. 32 is the
     *                  refresh-token default; 16 is the typical {@code jti} length
     * @return URL-safe Base64 string of {@code byteCount} cryptographically
     *         random bytes, with no padding
     * @throws IllegalArgumentException if {@code byteCount <= 0}
     */
    static String generate(int byteCount) {
        if (byteCount <= 0) {
            throw new IllegalArgumentException("byteCount must be positive: " + byteCount);
        }
        byte[] bytes = new byte[byteCount];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
