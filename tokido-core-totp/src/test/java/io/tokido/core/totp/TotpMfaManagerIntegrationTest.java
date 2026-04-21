package io.tokido.core.totp;

import io.tokido.core.EnrollmentContext;
import io.tokido.core.FactorStatus;
import io.tokido.core.StoredSecret;
import io.tokido.core.VerificationResult;
import io.tokido.core.engine.MfaManager;
import io.tokido.core.spi.SecretStore;
import io.tokido.core.test.InMemorySecretStore;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TotpMfaManagerIntegrationTest {

    @Test
    void totpWithoutConfirmationDoesNotWriteConfirmedMetadata() {
        InMemorySecretStore store = new InMemorySecretStore();
        TotpConfig config = TotpConfig.defaults().requiresConfirmation(false).issuer("App");
        TotpFactorProvider totp = new TotpFactorProvider(config, store);
        MfaManager mfa = MfaManager.builder().secretStore(store).factor(totp).build();

        mfa.enroll("u1", "totp", TotpEnrollmentContexts.enrollment(new TotpEnrollmentContext("alice@example.com")));

        StoredSecret stored = store.inspect("u1", "totp");
        assertNotNull(stored);
        assertNull(stored.metadata().get(SecretStore.Metadata.CONFIRMED));
    }

    @Test
    void totpWithoutConfirmationVerifyWithoutConfirmEnrollment() {
        InMemorySecretStore store = new InMemorySecretStore();
        TotpConfig config = TotpConfig.defaults().requiresConfirmation(false).issuer("App");
        TotpFactorProvider totp = new TotpFactorProvider(config, store);
        MfaManager mfa = MfaManager.builder().secretStore(store).factor(totp).build();

        mfa.enroll("u1", "totp", EnrollmentContext.empty());

        StoredSecret stored = store.inspect("u1", "totp");
        byte[] secret = stored.secret();
        long counter = System.currentTimeMillis() / 1000L / config.timeStepSeconds();
        String codeStr = String.format("%06d", TotpAlgorithm.generate(secret, counter, config));

        VerificationResult result = mfa.verify("u1", "totp", codeStr);
        assertTrue(result.valid());
    }

    @Test
    void totpWithoutConfirmationStatusIsConfirmed() {
        InMemorySecretStore store = new InMemorySecretStore();
        TotpConfig config = TotpConfig.defaults().requiresConfirmation(false).issuer("App");
        TotpFactorProvider totp = new TotpFactorProvider(config, store);
        MfaManager mfa = MfaManager.builder().secretStore(store).factor(totp).build();

        mfa.enroll("u1", "totp", EnrollmentContext.empty());

        FactorStatus st = mfa.status("u1", "totp");
        assertTrue(st.enrolled());
        assertTrue(st.confirmed());
    }

    @Test
    void confirmEnrollmentDoesNotAdvanceTotpReplayStateSoVerifyAcceptsSameCode() {
        InMemorySecretStore store = new InMemorySecretStore();
        TotpConfig config = TotpConfig.defaults().issuer("App");
        TotpFactorProvider totp = new TotpFactorProvider(config, store);
        MfaManager mfa = MfaManager.builder().secretStore(store).factor(totp).build();

        mfa.enroll("u1", "totp", EnrollmentContext.empty());

        StoredSecret enrolled = store.inspect("u1", "totp");
        byte[] secret = enrolled.secret();
        long counter = System.currentTimeMillis() / 1000L / config.timeStepSeconds();
        String code = String.format("%06d", TotpAlgorithm.generate(secret, counter, config));

        VerificationResult confirmResult = mfa.confirmEnrollment("u1", "totp", code);
        assertTrue(confirmResult.valid());

        StoredSecret afterConfirm = store.inspect("u1", "totp");
        assertEquals(-1L, ((Number) afterConfirm.metadata().get(SecretStore.Metadata.LAST_COUNTER)).longValue());
        assertNull(afterConfirm.metadata().get(SecretStore.Metadata.LAST_USED_AT));

        VerificationResult verifyResult = mfa.verify("u1", "totp", code);
        assertTrue(verifyResult.valid());

        VerificationResult replayResult = mfa.verify("u1", "totp", code);
        assertFalse(replayResult.valid());
        assertEquals("replay", replayResult.failureReason().orElse(null));
    }
}

