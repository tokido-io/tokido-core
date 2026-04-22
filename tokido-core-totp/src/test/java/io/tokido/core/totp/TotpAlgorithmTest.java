package io.tokido.core.totp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * RFC 6238 Appendix B test vectors.
 * Counter values are T(hex) from the RFC: time / 30.
 */
class TotpAlgorithmTest {

    // RFC 6238 test seeds
    private static final byte[] SEED_SHA1 = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED_SHA256 = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED_SHA512 = "1234567890123456789012345678901234567890123456789012345678901234"
            .getBytes(StandardCharsets.US_ASCII);

    // --- SHA-1 (8-digit codes) ---

    @Test
    void rfc6238_sha1_counter1() {
        assertEquals(94287082, TotpAlgorithm.generate(SEED_SHA1, 1, "HmacSHA1", 8));
    }

    @Test
    void rfc6238_sha1_counter37037036() {
        assertEquals(7081804, TotpAlgorithm.generate(SEED_SHA1, 0x23523ECL, "HmacSHA1", 8));
    }

    @Test
    void rfc6238_sha1_counter37037037() {
        assertEquals(14050471, TotpAlgorithm.generate(SEED_SHA1, 0x23523EDL, "HmacSHA1", 8));
    }

    @Test
    void rfc6238_sha1_counter41152263() {
        assertEquals(89005924, TotpAlgorithm.generate(SEED_SHA1, 0x273EF07L, "HmacSHA1", 8));
    }

    @Test
    void rfc6238_sha1_counter66666666() {
        assertEquals(69279037, TotpAlgorithm.generate(SEED_SHA1, 0x3F940AAL, "HmacSHA1", 8));
    }

    @Test
    void rfc6238_sha1_counter666666666() {
        assertEquals(65353130, TotpAlgorithm.generate(SEED_SHA1, 0x27BC86AAL, "HmacSHA1", 8));
    }

    // --- SHA-256 (8-digit codes) ---

    @Test
    void rfc6238_sha256_counter1() {
        assertEquals(46119246, TotpAlgorithm.generate(SEED_SHA256, 1, "HmacSHA256", 8));
    }

    @Test
    void rfc6238_sha256_counter41152263() {
        assertEquals(91819424, TotpAlgorithm.generate(SEED_SHA256, 0x273EF07L, "HmacSHA256", 8));
    }

    // --- SHA-512 (8-digit codes) ---

    @Test
    void rfc6238_sha512_counter1() {
        assertEquals(90693936, TotpAlgorithm.generate(SEED_SHA512, 1, "HmacSHA512", 8));
    }

    @Test
    void rfc6238_sha512_counter41152263() {
        assertEquals(93441116, TotpAlgorithm.generate(SEED_SHA512, 0x273EF07L, "HmacSHA512", 8));
    }

    // --- 6-digit mode ---

    @Test
    void sixDigitCodeTruncates() {
        // 94287082 % 1000000 = 287082
        int code = TotpAlgorithm.generate(SEED_SHA1, 1, "HmacSHA1", 6);
        assertEquals(287082, code);
    }

    @Test
    void generateWithConfig() {
        TotpConfig config = TotpConfig.defaults();
        int code = TotpAlgorithm.generate(SEED_SHA1, 1, config);
        assertEquals(287082, code); // 6-digit default
    }

    @Test
    void generateThrowsWhenMacAlgorithmInvalid() {
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> TotpAlgorithm.generate(SEED_SHA1, 1L, "NoSuchHmacAlgorithm", 6));
        assertEquals("TOTP computation failed", ex.getMessage());
    }
}
