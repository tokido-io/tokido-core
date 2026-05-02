package io.tokido.core.identity.engine.userinfo;

import io.tokido.core.identity.engine.TokenVerifier;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SignatureAlgorithm;
import io.tokido.core.identity.key.SigningKey;
import io.tokido.core.identity.protocol.UserInfoRequest;
import io.tokido.core.identity.protocol.UserInfoResult;
import io.tokido.core.identity.spi.AuthenticationResult;
import io.tokido.core.identity.spi.BrokeredAuthentication;
import io.tokido.core.identity.spi.User;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.identity.spi.UserStore;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link UserInfoHandler}.
 *
 * <p>Uses an inline-stub {@link TokenVerifier} (NOT the real
 * {@code NimbusTokenVerifier}) to avoid pulling identity-jwt into engine's
 * test classpath, which would create a Maven reactor cycle. End-to-end
 * verification against a real JWS is the conformance module's job.
 */
class UserInfoHandlerTest {

    private static final KeyStore EMPTY_KEY_STORE = new KeyStore() {
        @Override public SigningKey activeSigningKey(SignatureAlgorithm a) {
            throw new UnsupportedOperationException();
        }
        @Override public Set<SigningKey> allKeys() { return Set.of(); }
    };

    @Test
    void happyPathReturnsSuccessWithSubAndClaims() {
        TokenVerifier verifier = (token, ks) -> Map.of(
                "iss", "https://issuer.example/",
                "sub", "alice",
                "exp", 9_999_999_999L);
        Set<UserClaim> aliceClaims = Set.of(
                new UserClaim("name", "Alice"),
                new UserClaim("email", "alice@example.com"));
        UserStore userStore = stubUserStore(Map.of(
                "alice", new User("alice", "alice", true, Map.of())),
                Map.of("alice", aliceClaims));

        UserInfoResult result = new UserInfoHandler(verifier, EMPTY_KEY_STORE, userStore)
                .handle(new UserInfoRequest("any-token"));

        assertThat(result).isInstanceOf(UserInfoResult.Success.class);
        UserInfoResult.Success ok = (UserInfoResult.Success) result;
        assertThat(ok.subjectId()).isEqualTo("alice");
        assertThat(ok.claims()).isEqualTo(aliceClaims);
    }

    @Test
    void emptyClaimsFromVerifierReturnsInvalidToken() {
        TokenVerifier verifier = (token, ks) -> Map.of();
        UserStore userStore = stubUserStore(Map.of(), Map.of());

        UserInfoResult result = new UserInfoHandler(verifier, EMPTY_KEY_STORE, userStore)
                .handle(new UserInfoRequest("bad-token"));

        assertThat(result).isInstanceOf(UserInfoResult.Error.class);
        UserInfoResult.Error err = (UserInfoResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_token");
        assertThat(err.description()).isEqualTo("access token verification failed");
    }

    @Test
    void missingSubReturnsInvalidToken() {
        TokenVerifier verifier = (token, ks) -> Map.of("iss", "https://issuer.example/");
        UserStore userStore = stubUserStore(Map.of(), Map.of());

        UserInfoResult result = new UserInfoHandler(verifier, EMPTY_KEY_STORE, userStore)
                .handle(new UserInfoRequest("any-token"));

        assertThat(result).isInstanceOf(UserInfoResult.Error.class);
        UserInfoResult.Error err = (UserInfoResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_token");
        assertThat(err.description()).isEqualTo("missing or non-string sub");
    }

    @Test
    void nonStringSubReturnsInvalidToken() {
        TokenVerifier verifier = (token, ks) -> Map.of("sub", 42L);
        UserStore userStore = stubUserStore(Map.of(), Map.of());

        UserInfoResult result = new UserInfoHandler(verifier, EMPTY_KEY_STORE, userStore)
                .handle(new UserInfoRequest("any-token"));

        assertThat(result).isInstanceOf(UserInfoResult.Error.class);
        UserInfoResult.Error err = (UserInfoResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_token");
        assertThat(err.description()).isEqualTo("missing or non-string sub");
    }

    @Test
    void blankSubReturnsInvalidToken() {
        TokenVerifier verifier = (token, ks) -> Map.of("sub", "   ");
        UserStore userStore = stubUserStore(Map.of(), Map.of());

        UserInfoResult result = new UserInfoHandler(verifier, EMPTY_KEY_STORE, userStore)
                .handle(new UserInfoRequest("any-token"));

        assertThat(result).isInstanceOf(UserInfoResult.Error.class);
        UserInfoResult.Error err = (UserInfoResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_token");
        assertThat(err.description()).isEqualTo("missing or non-string sub");
    }

    @Test
    void unknownSubReturnsInvalidToken() {
        TokenVerifier verifier = (token, ks) -> Map.of("sub", "ghost");
        UserStore userStore = stubUserStore(Map.of(), Map.of());

        UserInfoResult result = new UserInfoHandler(verifier, EMPTY_KEY_STORE, userStore)
                .handle(new UserInfoRequest("any-token"));

        assertThat(result).isInstanceOf(UserInfoResult.Error.class);
        UserInfoResult.Error err = (UserInfoResult.Error) result;
        assertThat(err.code()).isEqualTo("invalid_token");
        assertThat(err.description()).isEqualTo("subject not found");
    }

    private static UserStore stubUserStore(Map<String, User> usersBySub,
                                           Map<String, Set<UserClaim>> claimsBySub) {
        Map<String, User> users = new HashMap<>(usersBySub);
        Map<String, Set<UserClaim>> claims = new HashMap<>(claimsBySub);
        return new UserStore() {
            @Override public User findById(String s) { return users.get(s); }
            @Override public User findByUsername(String u) { throw new UnsupportedOperationException(); }
            @Override public AuthenticationResult authenticate(String u, String c) { throw new UnsupportedOperationException(); }
            @Override public User findByExternalProvider(String p, String s) { throw new UnsupportedOperationException(); }
            @Override public User createFromExternalProvider(BrokeredAuthentication b) { throw new UnsupportedOperationException(); }
            @Override public Set<UserClaim> claims(String s) { return claims.getOrDefault(s, Set.of()); }
        };
    }
}
