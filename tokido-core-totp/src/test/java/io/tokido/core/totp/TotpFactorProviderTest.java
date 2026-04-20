package io.tokido.core.totp;

import io.tokido.core.*;
import io.tokido.core.test.InMemorySecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TotpFactorProviderTest {

    private InMemorySecretStore store;
    private TotpFactorProvider provider;

    @BeforeEach
    void setUp() {
        store = new InMemorySecretStore();
        provider = new TotpFactorProvider(TotpConfig.defaults().issuer("TestApp"), store);
    }

    @Test
    void factorType() {
        assertEquals("totp", provider.factorType());
    }

    @Test
    void requiresConfirmation() {
        assertTrue(provider.requiresConfirmation());
    }

    @Test
    void requiresConfirmationFollowsConfig() {
        TotpFactorProvider strict = new TotpFactorProvider(TotpConfig.defaults(), store);
        assertTrue(strict.requiresConfirmation());

        TotpFactorProvider immediate = new TotpFactorProvider(TotpConfig.defaults().requiresConfirmation(false), store);
        assertFalse(immediate.requiresConfirmation());
    }

    @Test
    void enrollGeneratesSecretAndQrCode() {
        TotpEnrollmentResult result = provider.enroll("user1", EnrollmentContext.empty());

        assertNotNull(result.secretUri());
        assertTrue(result.secretUri().startsWith("otpauth://totp/"));
        assertTrue(result.secretUri().contains("secret="));
        assertTrue(result.secretUri().contains("issuer=TestApp"));
        assertNotNull(result.qrCodeBase64());
        assertFalse(result.qrCodeBase64().isEmpty());
    }

    @Test
    void enrollStoresSecret() {
        provider.enroll("user1", EnrollmentContext.empty());

        assertTrue(store.hasSecret("user1", "totp"));
        StoredSecret stored = store.inspect("user1", "totp");
        assertEquals(20, stored.secret().length); // default secret length
        assertNull(stored.metadata().get("confirmed")); // confirmed is set by the engine, not the provider
        assertEquals(-1L, ((Number) stored.metadata().get("lastCounter")).longValue());
    }

    @Test
    void enrollUsesAccountNameFromContext() {
        TotpEnrollmentResult result = provider.enroll("user1",
                EnrollmentContext.of("accountName", "alice@example.com"));

        assertTrue(result.secretUri().contains("alice%40example.com"));
    }

    @Test
    void enrollUsesTotpEnrollmentContext() {
        TotpEnrollmentResult result = provider.enroll("user1",
                new TotpEnrollmentContext("alice@example.com").asEnrollmentContext());

        assertTrue(result.secretUri().contains("alice%40example.com"));
    }

    @Test
    void verifyAcceptsCurrentCode() {
        provider.enroll("user1", EnrollmentContext.empty());

        StoredSecret stored = store.inspect("user1", "totp");
        byte[] secret = stored.secret();
        long counter = System.currentTimeMillis() / 1000L / 30L;
        int code = TotpAlgorithm.generate(secret, counter, TotpConfig.defaults());
        String codeStr = String.format("%06d", code);

        TotpVerificationResult result = provider.verify("user1", codeStr, VerificationContext.empty());
        assertTrue(result.valid());
        assertNull(result.reason());
    }

    @Test
    void verifyRejectsWrongCode() {
        provider.enroll("user1", EnrollmentContext.empty());

        StoredSecret stored = store.inspect("user1", "totp");
        byte[] secret = stored.secret();
        TotpConfig cfg = TotpConfig.defaults();
        long currentCounter = System.currentTimeMillis() / 1000L / cfg.timeStepSeconds();
        int w = cfg.windowSize();
        // Codes that could match within window, plus one step on each side for clock drift.
        Set<Integer> possible = new HashSet<>();
        for (long c = currentCounter - w - 1; c <= currentCounter + w + 1; c++) {
            possible.add(TotpAlgorithm.generate(secret, c, cfg));
        }
        int wrong = -1;
        for (int candidate = 0; candidate < 1_000_000; candidate++) {
            if (!possible.contains(candidate)) {
                wrong = candidate;
                break;
            }
        }
        assertTrue(wrong >= 0, "expected at least one 6-digit code outside the verification window");

        String codeStr = String.format("%06d", wrong);
        TotpVerificationResult result = provider.verify("user1", codeStr, VerificationContext.empty());
        assertFalse(result.valid());
        assertEquals("invalid", result.reason());
    }

    @Test
    void verifyRejectsNonNumericCode() {
        provider.enroll("user1", EnrollmentContext.empty());

        TotpVerificationResult result = provider.verify("user1", "abcdef", VerificationContext.empty());
        assertFalse(result.valid());
        assertEquals("invalid", result.reason());
    }

    @Test
    void verifyDetectsReplay() {
        provider.enroll("user1", EnrollmentContext.empty());

        StoredSecret stored = store.inspect("user1", "totp");
        byte[] secret = stored.secret();
        long counter = System.currentTimeMillis() / 1000L / 30L;
        int code = TotpAlgorithm.generate(secret, counter, TotpConfig.defaults());
        String codeStr = String.format("%06d", code);

        // First verification succeeds
        TotpVerificationResult first = provider.verify("user1", codeStr, VerificationContext.empty());
        assertTrue(first.valid());

        // Same code again is replay
        TotpVerificationResult second = provider.verify("user1", codeStr, VerificationContext.empty());
        assertFalse(second.valid());
        assertEquals("replay", second.reason());
    }

    @Test
    void verifyNotEnrolledThrows() {
        assertThrows(NotEnrolledException.class, () ->
                provider.verify("user1", "123456", VerificationContext.empty()));
    }

    @Test
    void statusNotEnrolled() {
        FactorStatus status = provider.status("user1");
        assertFalse(status.enrolled());
    }

    @Test
    void statusEnrolled() {
        provider.enroll("user1", EnrollmentContext.empty());
        FactorStatus status = provider.status("user1");
        assertTrue(status.enrolled());
        assertFalse(status.confirmed()); // not yet confirmed
        assertNotNull(status.attributes().get("createdAt"));
    }

    @Test
    void verifyUpdatesLastUsedAt() {
        provider.enroll("user1", EnrollmentContext.empty());
        StoredSecret stored = store.inspect("user1", "totp");
        byte[] secret = stored.secret();
        long counter = System.currentTimeMillis() / 1000L / 30L;
        int code = TotpAlgorithm.generate(secret, counter, TotpConfig.defaults());
        String codeStr = String.format("%06d", code);

        provider.verify("user1", codeStr, VerificationContext.empty());

        FactorStatus status = provider.status("user1");
        assertNotNull(status.attributes().get("lastUsedAt"));
    }

    @Test
    void verifyAcceptsAdjacentWindowCode() {
        provider.enroll("user1", EnrollmentContext.empty());
        StoredSecret stored = store.inspect("user1", "totp");
        byte[] secret = stored.secret();
        // Use counter from the previous time step (within window=1)
        long counter = System.currentTimeMillis() / 1000L / 30L - 1;
        int code = TotpAlgorithm.generate(secret, counter, TotpConfig.defaults());
        String codeStr = String.format("%06d", code);

        TotpVerificationResult result = provider.verify("user1", codeStr, VerificationContext.empty());
        assertTrue(result.valid());
    }

    @Test
    void unenrollIsNoOp() {
        // unenroll just returns — engine handles SecretStore cleanup
        provider.enroll("user1", EnrollmentContext.empty());
        provider.unenroll("user1");
        // Secret still exists (engine would delete it)
        assertTrue(store.hasSecret("user1", "totp"));
    }

    @Test
    void enrollWithDefaultAccountName() {
        TotpEnrollmentResult result = provider.enroll("user1", EnrollmentContext.empty());
        // When no accountName in context, userId is used
        assertTrue(result.secretUri().contains("user1"));
    }

    @Test
    void verifyWithLeadingWhitespace() {
        provider.enroll("user1", EnrollmentContext.empty());
        StoredSecret stored = store.inspect("user1", "totp");
        byte[] secret = stored.secret();
        long counter = System.currentTimeMillis() / 1000L / 30L;
        int code = TotpAlgorithm.generate(secret, counter, TotpConfig.defaults());
        String codeStr = " " + String.format("%06d", code) + " ";

        TotpVerificationResult result = provider.verify("user1", codeStr, VerificationContext.empty());
        assertTrue(result.valid());
    }
}
