package io.tokido.core.identity.spi;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for any {@link UserStore} implementation. Subclasses provide
 * a {@link #createStore(Set, Map, Map, Map)} factory that returns a store
 * pre-seeded with users, password mappings, federated mappings, and per-subject
 * claim sets.
 */
public abstract class AbstractUserStoreContract {

    /**
     * Subclass-provided factory.
     *
     * @param users               users to seed
     * @param passwords           map of {@code username -> credential}; auth succeeds
     *                            iff the submitted credential matches
     * @param federatedMappings   map of {@code "providerId|externalSubject" -> User}
     * @param claimsBySubject     map of {@code subjectId -> claims}
     */
    protected abstract UserStore createStore(Set<User> users,
                                             Map<String, String> passwords,
                                             Map<String, User> federatedMappings,
                                             Map<String, Set<UserClaim>> claimsBySubject);

    private User alice() {
        return new User("sub-alice", "alice", true, Map.of());
    }

    private User bob() {
        return new User("sub-bob", "bob", true, Map.of());
    }

    @Test
    void findByIdReturnsSeededUser() {
        UserStore store = createStore(Set.of(alice()), Map.of(), Map.of(), Map.of());
        assertThat(store.findById("sub-alice")).isEqualTo(alice());
    }

    @Test
    void findByIdReturnsNullForUnknown() {
        UserStore store = createStore(Set.of(alice()), Map.of(), Map.of(), Map.of());
        assertThat(store.findById("nope")).isNull();
    }

    @Test
    void findByUsernameReturnsSeededUser() {
        UserStore store = createStore(Set.of(alice()), Map.of(), Map.of(), Map.of());
        assertThat(store.findByUsername("alice")).isEqualTo(alice());
    }

    @Test
    void authenticateSucceedsWithCorrectCredential() {
        UserStore store = createStore(
                Set.of(alice()),
                Map.of("alice", "password123"),
                Map.of(), Map.of());
        AuthenticationResult result = store.authenticate("alice", "password123");
        assertThat(result).isInstanceOf(AuthenticationResult.Success.class);
        assertThat(((AuthenticationResult.Success) result).user()).isEqualTo(alice());
    }

    @Test
    void authenticateReturnsInvalidCredentialsForWrongPassword() {
        UserStore store = createStore(
                Set.of(alice()),
                Map.of("alice", "password123"),
                Map.of(), Map.of());
        AuthenticationResult result = store.authenticate("alice", "wrong");
        assertThat(result).isInstanceOf(AuthenticationResult.InvalidCredentials.class);
    }

    @Test
    void authenticateReturnsInvalidCredentialsForUnknownUsername() {
        UserStore store = createStore(
                Set.of(alice()),
                Map.of("alice", "password123"),
                Map.of(), Map.of());
        AuthenticationResult result = store.authenticate("nope", "password123");
        assertThat(result).isInstanceOf(AuthenticationResult.InvalidCredentials.class);
    }

    @Test
    void findByExternalProviderReturnsLinkedUser() {
        UserStore store = createStore(
                Set.of(alice()),
                Map.of(),
                Map.of("google|alice@google", alice()),
                Map.of());
        assertThat(store.findByExternalProvider("google", "alice@google")).isEqualTo(alice());
    }

    @Test
    void findByExternalProviderReturnsNullForUnknown() {
        UserStore store = createStore(Set.of(), Map.of(), Map.of(), Map.of());
        assertThat(store.findByExternalProvider("google", "nope")).isNull();
    }

    @Test
    void createFromExternalProviderIsIdempotent() {
        UserStore store = createStore(Set.of(alice()), Map.of(),
                Map.of("google|ext-1", alice()), Map.of());
        BrokeredAuthentication b = new BrokeredAuthentication("google", "ext-1", Map.of());
        User first = store.createFromExternalProvider(b);
        User second = store.createFromExternalProvider(b);
        assertThat(first).isEqualTo(second);
    }

    @Test
    void claimsReturnsSeededClaims() {
        UserClaim email = new UserClaim("email", "alice@example.com");
        UserStore store = createStore(Set.of(alice()), Map.of(), Map.of(),
                Map.of("sub-alice", Set.of(email)));
        assertThat(store.claims("sub-alice")).containsExactly(email);
    }

    @Test
    void claimsReturnsEmptyForUnknownSubject() {
        UserStore store = createStore(Set.of(alice()), Map.of(), Map.of(), Map.of());
        assertThat(store.claims("nope")).isEmpty();
    }
}
