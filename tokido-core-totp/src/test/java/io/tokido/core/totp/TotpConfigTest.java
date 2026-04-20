package io.tokido.core.totp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TotpConfigTest {

    @Test
    void defaultValues() {
        TotpConfig config = TotpConfig.defaults();
        assertEquals(20, config.secretLength());
        assertEquals(6, config.codeLength());
        assertEquals(30, config.timeStepSeconds());
        assertEquals(1, config.windowSize());
        assertEquals("HmacSHA1", config.algorithm());
        assertEquals("App", config.issuer());
        assertTrue(config.requiresConfirmation());
    }

    @Test
    void fluentSetters() {
        TotpConfig config = TotpConfig.defaults()
                .secretLength(32)
                .codeLength(8)
                .timeStepSeconds(60)
                .windowSize(2)
                .algorithm("HmacSHA256")
                .issuer("MyApp");

        assertEquals(32, config.secretLength());
        assertEquals(8, config.codeLength());
        assertEquals(60, config.timeStepSeconds());
        assertEquals(2, config.windowSize());
        assertEquals("HmacSHA256", config.algorithm());
        assertEquals("MyApp", config.issuer());
    }

    @Test
    void requiresConfirmationCanBeDisabled() {
        TotpConfig config = TotpConfig.defaults().requiresConfirmation(false);
        assertFalse(config.requiresConfirmation());
    }
}
