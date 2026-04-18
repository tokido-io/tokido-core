package io.tokido.core.totp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class Base32Test {

    @Test
    void encodeRfc4648TestVectors() {
        // RFC 4648 Section 10 test vectors (without padding)
        assertEquals("", Base32.encode(new byte[0]));
        assertEquals("MY", Base32.encode("f".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXQ", Base32.encode("fo".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6", Base32.encode("foo".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6YQ", Base32.encode("foob".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6YTB", Base32.encode("fooba".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6YTBOI", Base32.encode("foobar".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void encode20ByteSecret() {
        byte[] secret = new byte[20];
        for (int i = 0; i < 20; i++) secret[i] = (byte) i;
        String encoded = Base32.encode(secret);
        assertEquals(32, encoded.length()); // 20 bytes = 32 base32 chars
    }
}
