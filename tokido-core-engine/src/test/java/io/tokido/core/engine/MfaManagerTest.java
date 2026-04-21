package io.tokido.core.engine;

import io.tokido.core.*;
import io.tokido.core.spi.FactorProvider;
import io.tokido.core.test.CollectingAuditSink;
import io.tokido.core.test.InMemorySecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MfaManagerTest {

    private InMemorySecretStore store;
    private CollectingAuditSink auditSink;

    @BeforeEach
    void setUp() {
        store = new InMemorySecretStore();
        auditSink = new CollectingAuditSink();
    }

    private FactorProvider<TestEnrollmentResult, TestVerificationResult> factor(
            String type, boolean requiresConfirmation) {
        return new FactorProvider<>() {
            @Override public String factorType() { return type; }
            @Override public boolean requiresConfirmation() { return requiresConfirmation; }

            @Override
            public TestEnrollmentResult enroll(String userId, EnrollmentContext ctx) {
                store.store(userId, type, new byte[]{1, 2, 3}, Map.of());
                return new TestEnrollmentResult("enrolled:" + userId);
            }

            @Override
            public TestVerificationResult verify(String userId, String credential, VerificationContext ctx) {
                boolean valid = "valid".equals(credential);
                return new TestVerificationResult(valid, valid ? null : "invalid");
            }

            @Override public void unenroll(String userId) {}

            @Override
            public FactorStatus status(String userId) {
                return store.hasSecret(userId, type)
                        ? new FactorStatus(true, true, Map.of())
                        : FactorStatus.notEnrolled();
            }
        };
    }

    private MfaManager buildManager(FactorProvider<?, ?>... factors) {
        var builder = MfaManager.builder()
                .secretStore(store)
                .auditSink(auditSink);
        for (var f : factors) {
            builder.factor(f);
        }
        return builder.build();
    }

    // --- Builder validation ---

    @Test
    void buildRequiresSecretStore() {
        assertThrows(NullPointerException.class, () ->
                MfaManager.builder().factor(factor("x", false)).build());
    }

    @Test
    void buildRequiresAtLeastOneFactor() {
        assertThrows(IllegalArgumentException.class, () ->
                MfaManager.builder().secretStore(store).build());
    }

    @Test
    void buildWithNoAuditSinkUsesNoop() {
        MfaManager m = MfaManager.builder()
                .secretStore(store)
                .factor(factor("x", false))
                .build();
        assertNotNull(m);
    }

    // --- Enrollment ---

    @Test
    void enrollCreatesSecretAndEmitsEvent() {
        var mfa = buildManager(factor("test-simple", false));
        TestEnrollmentResult result = mfa.enroll("user1", "test-simple", EnrollmentContext.empty());

        assertNotNull(result);
        assertEquals("enrolled:user1", result.data());
        assertTrue(store.hasSecret("user1", "test-simple"));
        assertEquals(1, auditSink.size());
        assertEquals("enrolled", auditSink.lastEvent().action());
    }

    @Test
    void enrollRejectsDuplicate() {
        var mfa = buildManager(factor("test-simple", false));
        mfa.enroll("user1", "test-simple", EnrollmentContext.empty());

        assertThrows(AlreadyEnrolledException.class, () ->
                mfa.enroll("user1", "test-simple", EnrollmentContext.empty()));
    }

    @Test
    void enrollUnknownFactorThrows() {
        var mfa = buildManager(factor("test-simple", false));
        assertThrows(FactorNotRegisteredException.class, () ->
                mfa.enroll("user1", "unknown", EnrollmentContext.empty()));
    }

    @Test
    void enrollWithConfirmationSetsUnconfirmed() {
        var mfa = buildManager(factor("test-confirm", true));
        mfa.enroll("user1", "test-confirm", EnrollmentContext.empty());

        StoredSecret stored = store.inspect("user1", "test-confirm");
        assertNotNull(stored);
        assertEquals(false, stored.metadata().get("confirmed"));
    }

    @Test
    void enrollMultipleRollsBackOnFailure() {
        FactorProvider<TestEnrollmentResult, TestVerificationResult> ok = new FactorProvider<>() {
            @Override public String factorType() { return "ok"; }
            @Override public boolean requiresConfirmation() { return false; }
            @Override public TestEnrollmentResult enroll(String userId, EnrollmentContext ctx) {
                store.store(userId, factorType(), new byte[]{1}, Map.of());
                return new TestEnrollmentResult("ok");
            }
            @Override public TestVerificationResult verify(String userId, String credential, VerificationContext ctx) {
                return new TestVerificationResult(true, null);
            }
            @Override public void unenroll(String userId) {}
            @Override public FactorStatus status(String userId) { return store.hasSecret(userId, factorType()) ? new FactorStatus(true, true, Map.of()) : FactorStatus.notEnrolled(); }
        };

        FactorProvider<TestEnrollmentResult, TestVerificationResult> boom = new FactorProvider<>() {
            @Override public String factorType() { return "boom"; }
            @Override public boolean requiresConfirmation() { return false; }
            @Override public TestEnrollmentResult enroll(String userId, EnrollmentContext ctx) {
                // Simulate provider writing, then throwing.
                store.store(userId, factorType(), new byte[]{2}, Map.of());
                throw new RuntimeException("boom");
            }
            @Override public TestVerificationResult verify(String userId, String credential, VerificationContext ctx) {
                return new TestVerificationResult(true, null);
            }
            @Override public void unenroll(String userId) {}
            @Override public FactorStatus status(String userId) { return store.hasSecret(userId, factorType()) ? new FactorStatus(true, true, Map.of()) : FactorStatus.notEnrolled(); }
        };

        var mfa = buildManager(ok, boom);

        assertThrows(RuntimeException.class, () -> mfa.enroll("user1", java.util.List.of(
                new FactorEnrollment("ok", EnrollmentContext.empty()),
                new FactorEnrollment("boom", EnrollmentContext.empty())
        )));

        assertFalse(store.hasSecret("user1", "ok"));
        assertFalse(store.hasSecret("user1", "boom"));
    }

    @Test
    void enrollMultiplePrecheckAvoidsPartialWrites() {
        var mfa = buildManager(factor("test-simple", false), factor("test-confirm", true));
        mfa.enroll("user1", "test-simple", EnrollmentContext.empty());

        assertThrows(AlreadyEnrolledException.class, () -> mfa.enroll("user1", java.util.List.of(
                new FactorEnrollment("test-simple", EnrollmentContext.empty()),
                new FactorEnrollment("test-confirm", EnrollmentContext.empty())
        )));

        // confirm factor should not have been written.
        assertFalse(store.hasSecret("user1", "test-confirm"));
    }

    // --- Confirmation ---

    @Test
    void confirmEnrollmentWithValidCredential() {
        var mfa = buildManager(factor("test-confirm", true));
        mfa.enroll("user1", "test-confirm", EnrollmentContext.empty());

        VerificationResult result = mfa.confirmEnrollment("user1", "test-confirm", "valid");
        assertTrue(result.valid());

        StoredSecret stored = store.inspect("user1", "test-confirm");
        assertEquals(true, stored.metadata().get("confirmed"));
        assertEquals(1, auditSink.eventsFor("user1", "confirmed").size());
    }

    @Test
    void confirmEnrollmentWithInvalidCredential() {
        var mfa = buildManager(factor("test-confirm", true));
        mfa.enroll("user1", "test-confirm", EnrollmentContext.empty());

        VerificationResult result = mfa.confirmEnrollment("user1", "test-confirm", "wrong");
        assertFalse(result.valid());

        StoredSecret stored = store.inspect("user1", "test-confirm");
        assertEquals(false, stored.metadata().get("confirmed"));
        assertEquals(1, auditSink.eventsFor("user1", "confirmation_failed").size());
    }

    @Test
    void confirmNotEnrolledThrows() {
        var mfa = buildManager(factor("test-confirm", true));
        assertThrows(NotEnrolledException.class, () ->
                mfa.confirmEnrollment("user1", "test-confirm", "valid"));
    }

    @Test
    void confirmFactorThatDoesNotRequireConfirmationThrows() {
        var mfa = buildManager(factor("test-simple", false));
        mfa.enroll("user1", "test-simple", EnrollmentContext.empty());

        assertThrows(MfaException.class, () ->
                mfa.confirmEnrollment("user1", "test-simple", "valid"));
    }

    @Test
    void confirmAlreadyConfirmedThrows() {
        var mfa = buildManager(factor("test-confirm", true));
        mfa.enroll("user1", "test-confirm", EnrollmentContext.empty());
        mfa.confirmEnrollment("user1", "test-confirm", "valid");

        assertThrows(MfaException.class, () ->
                mfa.confirmEnrollment("user1", "test-confirm", "valid"));
    }

    // --- Verification ---

    @Test
    void verifySimpleFactorAcceptsValidCredential() {
        var mfa = buildManager(factor("test-simple", false));
        mfa.enroll("user1", "test-simple", EnrollmentContext.empty());

        VerificationResult result = mfa.verify("user1", "test-simple", "valid");
        assertTrue(result.valid());
        assertEquals("verified", auditSink.lastEvent().action());
    }

    @Test
    void verifySimpleFactorRejectsInvalidCredential() {
        var mfa = buildManager(factor("test-simple", false));
        mfa.enroll("user1", "test-simple", EnrollmentContext.empty());

        VerificationResult result = mfa.verify("user1", "test-simple", "wrong");
        assertFalse(result.valid());
        assertEquals("verification_failed", auditSink.lastEvent().action());
    }

    @Test
    void verifyRejectsUnconfirmedEnrollment() {
        var mfa = buildManager(factor("test-confirm", true));
        mfa.enroll("user1", "test-confirm", EnrollmentContext.empty());

        VerificationResult result = mfa.verify("user1", "test-confirm", "valid");
        assertFalse(result.valid());
    }

    @Test
    void verifyAcceptsConfirmedEnrollment() {
        var mfa = buildManager(factor("test-confirm", true));
        mfa.enroll("user1", "test-confirm", EnrollmentContext.empty());
        mfa.confirmEnrollment("user1", "test-confirm", "valid");

        VerificationResult result = mfa.verify("user1", "test-confirm", "valid");
        assertTrue(result.valid());
    }

    @Test
    void verifyNotEnrolledThrows() {
        var mfa = buildManager(factor("test-simple", false));
        assertThrows(NotEnrolledException.class, () ->
                mfa.verify("user1", "test-simple", "valid"));
    }

    // --- Unenroll ---

    @Test
    void unenrollDeletesSecretAndEmitsEvent() {
        var mfa = buildManager(factor("test-simple", false));
        mfa.enroll("user1", "test-simple", EnrollmentContext.empty());
        mfa.unenroll("user1", "test-simple");

        assertFalse(store.hasSecret("user1", "test-simple"));
        assertEquals("unenrolled", auditSink.lastEvent().action());
    }

    @Test
    void unenrollNotEnrolledThrows() {
        var mfa = buildManager(factor("test-simple", false));
        assertThrows(NotEnrolledException.class, () ->
                mfa.unenroll("user1", "test-simple"));
    }

    // --- Status ---

    @Test
    void statusNotEnrolled() {
        var mfa = buildManager(factor("test-simple", false));
        FactorStatus status = mfa.status("user1", "test-simple");
        assertFalse(status.enrolled());
    }

    @Test
    void statusEnrolled() {
        var mfa = buildManager(factor("test-simple", false));
        mfa.enroll("user1", "test-simple", EnrollmentContext.empty());
        FactorStatus status = mfa.status("user1", "test-simple");
        assertTrue(status.enrolled());
    }

    @Test
    void statusUnknownFactorThrows() {
        var mfa = buildManager(factor("test-simple", false));
        assertThrows(FactorNotRegisteredException.class, () ->
                mfa.status("user1", "unknown"));
    }

    @Test
    void allFactorsReturnsAllRegistered() {
        var mfa = buildManager(factor("test-simple", false), factor("test-confirm", true));
        Map<String, FactorStatus> all = mfa.allFactors("user1");
        assertEquals(2, all.size());
        assertTrue(all.containsKey("test-simple"));
        assertTrue(all.containsKey("test-confirm"));
    }

    // --- Test helpers ---

    record TestEnrollmentResult(String data) implements EnrollmentResult {}
    record TestVerificationResult(boolean valid, String reason) implements VerificationResult {}
}
