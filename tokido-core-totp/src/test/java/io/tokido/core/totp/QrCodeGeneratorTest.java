package io.tokido.core.totp;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class QrCodeGeneratorTest {

    @Test
    void generatesPngBase64() {
        String base64 = QrCodeGenerator.toPngBase64("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Test");
        assertNotNull(base64);
        assertFalse(base64.isEmpty());

        // Verify it's valid base64 that decodes to a PNG
        byte[] png = Base64.getDecoder().decode(base64);
        // PNG magic bytes
        assertEquals((byte) 0x89, png[0]);
        assertEquals((byte) 0x50, png[1]); // P
        assertEquals((byte) 0x4E, png[2]); // N
        assertEquals((byte) 0x47, png[3]); // G
    }

    @Test
    void handlesSpecialCharacters() {
        String base64 = QrCodeGenerator.toPngBase64("otpauth://totp/user%40example.com?secret=ABC&issuer=My%20App");
        assertNotNull(base64);
        assertFalse(base64.isEmpty());
    }
}
