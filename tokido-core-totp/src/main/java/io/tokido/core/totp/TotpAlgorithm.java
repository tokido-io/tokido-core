package io.tokido.core.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

/**
 * RFC 6238 TOTP / RFC 4226 HOTP computation.
 * Pure function — no state, no I/O.
 */
public final class TotpAlgorithm {

    private TotpAlgorithm() {
    }

    /**
     * Generate a TOTP code for the given secret and counter.
     *
     * @param secret    the shared secret
     * @param counter   the time-based counter (epoch_seconds / time_step)
     * @param algorithm HMAC algorithm name (e.g., "HmacSHA1", "HmacSHA256", "HmacSHA512")
     * @param digits    number of digits in the output code
     * @return the TOTP code as an integer
     */
    public static int generate(byte[] secret, long counter, String algorithm, int digits) {
        try {
            byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(secret, algorithm));
            byte[] hash = mac.doFinal(counterBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int code = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int mod = 1;
            for (int i = 0; i < digits; i++) {
                mod *= 10;
            }
            return code % mod;
        } catch (Exception e) {
            throw new RuntimeException("TOTP computation failed", e);
        }
    }

    /**
     * Generate a TOTP code using configuration defaults.
     */
    public static int generate(byte[] secret, long counter, TotpConfig config) {
        return generate(secret, counter, config.algorithm(), config.codeLength());
    }
}
