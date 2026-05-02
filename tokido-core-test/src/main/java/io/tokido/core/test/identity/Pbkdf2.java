package io.tokido.core.test.identity;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Minimal PBKDF2 password hashing for the test UserStore. NOT for production.
 */
final class Pbkdf2 {

    private static final int ITERATIONS = 100_000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final SecureRandom RNG = new SecureRandom();
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    static String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        RNG.nextBytes(salt);
        byte[] hash = derive(password, salt);
        return Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(hash);
    }

    static boolean verify(String password, String stored) {
        String[] parts = stored.split(":", 2);
        if (parts.length != 2) return false;
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] expected = Base64.getDecoder().decode(parts[1]);
        byte[] actual = derive(password, salt);
        if (actual.length != expected.length) return false;
        int diff = 0;
        for (int i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
        return diff == 0;
    }

    private static byte[] derive(String password, byte[] salt) {
        try {
            return SecretKeyFactory.getInstance(ALGORITHM)
                    .generateSecret(new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH_BITS))
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 derive failed", e);
        }
    }
}
