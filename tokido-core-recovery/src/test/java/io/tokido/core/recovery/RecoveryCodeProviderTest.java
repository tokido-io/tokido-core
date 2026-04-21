package io.tokido.core.recovery;

import io.tokido.core.*;
import io.tokido.core.test.InMemorySecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RecoveryCodeProviderTest {

    private InMemorySecretStore store;
    private RecoveryCodeProvider provider;

    @BeforeEach
    void setUp() {
        store = new InMemorySecretStore();
        provider = new RecoveryCodeProvider(
                RecoveryConfig.defaults().bcryptCost(4), // low cost for fast tests
                store);
    }

    @Test
    void factorType() {
        assertEquals("recovery", provider.factorType());
    }

    @Test
    void doesNotRequireConfirmation() {
        assertFalse(provider.requiresConfirmation());
    }

    @Test
    void enrollGeneratesTenCodes() {
        RecoveryEnrollmentResult result = provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());

        List<String> codes = result.codes();
        assertEquals(10, codes.size());
        // All codes are 8 digits
        for (String code : codes) {
            assertEquals(8, code.length());
            assertTrue(code.matches("\\d{8}"));
        }
        // All codes are unique
        assertEquals(10, new HashSet<>(codes).size());
    }

    @Test
    void enrollStoresHashedCodes() {
        provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());

        assertTrue(store.hasSecret("user1", "recovery"));
        StoredSecret stored = store.inspect("user1", "recovery");
        @SuppressWarnings("unchecked")
        List<String> hashedCodes = (List<String>) stored.metadata().get("hashedCodes");
        assertEquals(10, hashedCodes.size());
        // Hashed codes start with bcrypt prefix
        for (String hash : hashedCodes) {
            assertTrue(hash.startsWith("$2a$"));
        }
    }

    @Test
    void verifyAcceptsValidCode() {
        RecoveryEnrollmentResult enrollment = provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());
        String firstCode = enrollment.codes().get(0);

        RecoveryVerificationResult result = provider.verify("user1", firstCode, VerificationContext.empty());
        assertTrue(result.valid());
        assertEquals(9, result.codesRemaining());
    }

    @Test
    void verifyConsumesCode() {
        RecoveryEnrollmentResult enrollment = provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());
        String firstCode = enrollment.codes().get(0);

        // First use succeeds
        RecoveryVerificationResult first = provider.verify("user1", firstCode, VerificationContext.empty());
        assertTrue(first.valid());

        // Second use of same code fails
        RecoveryVerificationResult second = provider.verify("user1", firstCode, VerificationContext.empty());
        assertFalse(second.valid());
        assertEquals(9, second.codesRemaining()); // still 9, code was already consumed
    }

    @Test
    void verifyRejectsInvalidCode() {
        provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());

        RecoveryVerificationResult result = provider.verify("user1", "00000000", VerificationContext.empty());
        assertFalse(result.valid());
        assertEquals(10, result.codesRemaining());
    }

    @Test
    void verifyMultipleCodesDecrementsCount() {
        RecoveryEnrollmentResult enrollment = provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());

        for (int i = 0; i < 3; i++) {
            RecoveryVerificationResult result = provider.verify(
                    "user1", enrollment.codes().get(i), VerificationContext.empty());
            assertTrue(result.valid());
            assertEquals(10 - (i + 1), result.codesRemaining());
        }
    }

    @Test
    void verifyNotEnrolledThrows() {
        assertThrows(NotEnrolledException.class, () ->
                provider.verify("user1", "12345678", VerificationContext.empty()));
    }

    @Test
    void statusNotEnrolled() {
        FactorStatus status = provider.status("user1");
        assertFalse(status.enrolled());
    }

    @Test
    void statusEnrolled() {
        provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());
        FactorStatus status = provider.status("user1");
        assertTrue(status.enrolled());
        assertTrue(status.confirmed()); // recovery codes don't need confirmation
        assertEquals(10, status.attributes().get("codesRemaining"));
    }

    @Test
    void statusAfterCodeUse() {
        RecoveryEnrollmentResult enrollment = provider.enroll("user1", RecoveryEnrollmentContexts.enrollment());
        provider.verify("user1", enrollment.codes().get(0), VerificationContext.empty());

        FactorStatus status = provider.status("user1");
        assertEquals(9, status.attributes().get("codesRemaining"));
    }

    @Test
    void customConfig() {
        RecoveryCodeProvider custom = new RecoveryCodeProvider(
                RecoveryConfig.defaults().codeCount(5).codeLength(6).bcryptCost(4),
                store);

        RecoveryEnrollmentResult result = custom.enroll("user1", RecoveryEnrollmentContexts.enrollment());
        assertEquals(5, result.codes().size());
        for (String code : result.codes()) {
            assertEquals(6, code.length());
        }
    }
}
