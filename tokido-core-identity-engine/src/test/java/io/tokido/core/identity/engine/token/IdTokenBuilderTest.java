package io.tokido.core.identity.engine.token;

import io.tokido.core.identity.spi.AuthenticationResult;
import io.tokido.core.identity.spi.BrokeredAuthentication;
import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.ProtectedResource;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.User;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.identity.spi.UserStore;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shape + content tests for the JSON body produced by {@link IdTokenBuilder}.
 * The engine is Jackson-free so the encoder is hand-rolled; these tests pin
 * the wire shape and the userinfo-claim expansion.
 */
class IdTokenBuilderTest {

    private static final URI ISSUER = URI.create("https://issuer.example/");
    private static final Instant NOW = Instant.parse("2026-05-02T12:00:00Z");
    private static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration LIFETIME = Duration.ofMinutes(5);
    private static final Instant AUTH_TIME = Instant.parse("2026-05-02T11:55:00Z");

    @Test
    void happyPathEmitsAllCoreClaimsAndAuthTimeAndNonce() {
        ResourceStore resources = scopeResolver(Map.of(
                "openid", new IdentityScope("openid", null, Set.of("sub"))));
        UserStore users = noClaimsUserStore();

        String json = new IdTokenBuilder(ISSUER, resources, users, FIXED, LIFETIME)
                .build("user-1", "client-1", Set.of("openid"), "n-123", AUTH_TIME);

        long iat = NOW.getEpochSecond();
        long exp = NOW.plus(LIFETIME).getEpochSecond();
        long authTime = AUTH_TIME.getEpochSecond();
        assertThat(json)
                .contains("\"iss\":\"https://issuer.example/\"")
                .contains("\"sub\":\"user-1\"")
                .contains("\"aud\":\"client-1\"")
                .contains("\"iat\":" + iat)
                .contains("\"exp\":" + exp)
                .contains("\"auth_time\":" + authTime)
                .contains("\"nonce\":\"n-123\"");
    }

    @Test
    void omitsNonceWhenNonceArgIsNull() {
        ResourceStore resources = scopeResolver(Map.of(
                "openid", new IdentityScope("openid", null, Set.of("sub"))));
        UserStore users = noClaimsUserStore();

        String json = new IdTokenBuilder(ISSUER, resources, users, FIXED, LIFETIME)
                .build("user-1", "client-1", Set.of("openid"), null, AUTH_TIME);

        assertThat(json).doesNotContain("\"nonce\"");
    }

    @Test
    void omitsAuthTimeWhenAuthTimeArgIsNull() {
        ResourceStore resources = scopeResolver(Map.of(
                "openid", new IdentityScope("openid", null, Set.of("sub"))));
        UserStore users = noClaimsUserStore();

        String json = new IdTokenBuilder(ISSUER, resources, users, FIXED, LIFETIME)
                .build("user-1", "client-1", Set.of("openid"), "n-1", null);

        assertThat(json).doesNotContain("\"auth_time\"");
    }

    @Test
    void claimsExpansionFiltersByGrantedScopesUnlockedClaimNames() {
        // openid -> {sub}; profile -> {name, family_name}.
        // The user has {name, family_name, email}. With granted = {openid, profile}
        // the ID token must include name + family_name but NOT email.
        ResourceStore resources = scopeResolver(Map.of(
                "openid",  new IdentityScope("openid",  null, Set.of("sub")),
                "profile", new IdentityScope("profile", null, Set.of("name", "family_name")),
                "email",   new IdentityScope("email",   null, Set.of("email"))));

        UserStore users = userStoreWithClaims(Set.of(
                new UserClaim("name", "Alice"),
                new UserClaim("family_name", "Smith"),
                new UserClaim("email", "alice@example.com")));

        String json = new IdTokenBuilder(ISSUER, resources, users, FIXED, LIFETIME)
                .build("user-1", "client-1", Set.of("openid", "profile"), null, null);

        assertThat(json)
                .contains("\"name\":\"Alice\"")
                .contains("\"family_name\":\"Smith\"")
                .doesNotContain("\"email\"");
    }

    @Test
    void unknownScopeIsSkippedSilently() {
        // resourceStore has only "openid"; "phone" is granted but unmapped.
        // The builder should skip without throwing.
        ResourceStore resources = scopeResolver(Map.of(
                "openid", new IdentityScope("openid", null, Set.of("sub"))));
        UserStore users = noClaimsUserStore();

        String json = new IdTokenBuilder(ISSUER, resources, users, FIXED, LIFETIME)
                .build("user-1", "client-1", Set.of("openid", "phone"), null, null);

        assertThat(json).contains("\"sub\":\"user-1\"");
    }

    @Test
    void claimValueAlwaysEncodedAsJsonStringEvenIfTextLooksNumeric() {
        // RC1 documented limitation: a value of "42" is emitted as the JSON
        // string "42", not the number 42. Pinning this behavior so M3 typed-
        // claim work explicitly changes it.
        ResourceStore resources = scopeResolver(Map.of(
                "profile", new IdentityScope("profile", null, Set.of("age"))));
        UserStore users = userStoreWithClaims(Set.of(new UserClaim("age", "42")));

        String json = new IdTokenBuilder(ISSUER, resources, users, FIXED, LIFETIME)
                .build("user-1", "client-1", Set.of("profile"), null, null);

        assertThat(json).contains("\"age\":\"42\"");
    }

    @Test
    void jsonShapeIsObjectStartingAndEndingInBraces() {
        String json = new IdTokenBuilder(
                ISSUER,
                scopeResolver(Map.of("openid", new IdentityScope("openid", null, Set.of("sub")))),
                noClaimsUserStore(),
                FIXED, LIFETIME)
                .build("user-1", "client-1", Set.of("openid"), null, null);

        assertThat(json).startsWith("{").endsWith("}");
    }

    // ---- helpers ----

    private static ResourceStore scopeResolver(Map<String, IdentityScope> byName) {
        Map<String, IdentityScope> idx = new HashMap<>(byName);
        return new ResourceStore() {
            @Override public IdentityScope findIdentityScope(String name) { return idx.get(name); }
            @Override public ProtectedResource findProtectedResource(String n) { throw new UnsupportedOperationException(); }
            @Override public Set<IdentityScope> findIdentityScopesByName(Set<String> ns) { throw new UnsupportedOperationException(); }
            @Override public Set<ProtectedResource> findResourcesByScope(Set<String> ns) { throw new UnsupportedOperationException(); }
        };
    }

    private static UserStore noClaimsUserStore() {
        return userStoreWithClaims(Set.of());
    }

    private static UserStore userStoreWithClaims(Set<UserClaim> claims) {
        return new UserStore() {
            @Override public User findById(String s) { throw new UnsupportedOperationException(); }
            @Override public User findByUsername(String u) { throw new UnsupportedOperationException(); }
            @Override public AuthenticationResult authenticate(String u, String c) { throw new UnsupportedOperationException(); }
            @Override public User findByExternalProvider(String p, String s) { throw new UnsupportedOperationException(); }
            @Override public User createFromExternalProvider(BrokeredAuthentication b) { throw new UnsupportedOperationException(); }
            @Override public Set<UserClaim> claims(String s) { return claims; }
        };
    }
}
