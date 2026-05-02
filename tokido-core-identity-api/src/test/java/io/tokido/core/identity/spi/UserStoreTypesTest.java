package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class UserStoreTypesTest {

    @Test
    void userClaimRejectsBlankType() {
        assertThatIllegalArgumentException().isThrownBy(() -> new UserClaim("", "v"));
    }

    @Test
    void userClaimRejectsNullValue() {
        assertThatNullPointerException().isThrownBy(() -> new UserClaim("name", null));
    }

    @Test
    void userRejectsBlankSubjectId() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new User("", "alice", true, Map.of()));
    }

    @Test
    void userCopiesProfileToImmutable() {
        User u = new User("sub-1", "alice", true, Map.of("email", "alice@example.com"));
        assertThat(u.profile()).containsEntry("email", "alice@example.com");
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> u.profile().put("k", "v"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void brokeredAuthenticationRejectsBlankProviderId() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new BrokeredAuthentication("", "ext-1", Map.of()));
    }

    @Test
    void brokeredAuthenticationRejectsBlankExternalSubject() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new BrokeredAuthentication("google", "", Map.of()));
    }

    @Test
    void authenticationResultSuccessRequiresUser() {
        assertThatNullPointerException().isThrownBy(
                () -> new AuthenticationResult.Success(null));
    }

    @Test
    void authenticationResultFailureVariantsAreNoArg() {
        AuthenticationResult.InvalidCredentials a = new AuthenticationResult.InvalidCredentials();
        AuthenticationResult.AccountLocked b = new AuthenticationResult.AccountLocked();
        AuthenticationResult.AccountDisabled c = new AuthenticationResult.AccountDisabled();
        assertThat(a).isNotNull();
        assertThat(b).isNotNull();
        assertThat(c).isNotNull();
    }

    @org.junit.jupiter.api.Nested
    class SmokeContract extends AbstractUserStoreContract {
        @Override
        protected UserStore createStore(java.util.Set<User> users,
                                        java.util.Map<String, String> passwords,
                                        java.util.Map<String, User> federatedMappings,
                                        java.util.Map<String, java.util.Set<UserClaim>> claimsBySubject) {
            java.util.Map<String, User> bySub = new java.util.HashMap<>();
            java.util.Map<String, User> byName = new java.util.HashMap<>();
            for (User u : users) {
                bySub.put(u.subjectId(), u);
                byName.put(u.username(), u);
            }
            java.util.Map<String, User> bySubSnap = java.util.Map.copyOf(bySub);
            java.util.Map<String, User> byNameSnap = java.util.Map.copyOf(byName);
            java.util.Map<String, String> pwSnap = java.util.Map.copyOf(passwords);
            java.util.Map<String, User> fedSnap = java.util.Map.copyOf(federatedMappings);
            java.util.Map<String, java.util.Set<UserClaim>> claimsSnap =
                    java.util.Map.copyOf(claimsBySubject);
            return new UserStore() {
                @Override public User findById(String s) { return bySubSnap.get(s); }
                @Override public User findByUsername(String u) { return byNameSnap.get(u); }
                @Override
                public AuthenticationResult authenticate(String username, String credential) {
                    String expected = pwSnap.get(username);
                    if (expected == null || !expected.equals(credential)) {
                        return new AuthenticationResult.InvalidCredentials();
                    }
                    return new AuthenticationResult.Success(byNameSnap.get(username));
                }
                @Override
                public User findByExternalProvider(String p, String s) {
                    return fedSnap.get(p + "|" + s);
                }
                @Override
                public User createFromExternalProvider(BrokeredAuthentication b) {
                    User existing = fedSnap.get(b.providerId() + "|" + b.externalSubject());
                    if (existing != null) return existing;
                    throw new UnsupportedOperationException(
                            "smoke contract does not support creation; seed federatedMappings");
                }
                @Override
                public java.util.Set<UserClaim> claims(String s) {
                    return claimsSnap.getOrDefault(s, java.util.Set.of());
                }
            };
        }
    }
}
