package io.tokido.core.identity.engine.token;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shape + content tests for the JSON body produced by
 * {@link AccessTokenBuilder}. The engine module is Jackson-free so the
 * encoder is hand-rolled — these tests pin the wire shape and keep it
 * RFC 9068-compliant.
 */
class AccessTokenBuilderTest {

    private static final URI ISSUER = URI.create("https://issuer.example/");
    private static final Instant NOW = Instant.parse("2026-05-02T12:00:00Z");
    private static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void emitsAllRequiredClaims() {
        String json = new AccessTokenBuilder(ISSUER, FIXED).build(
                "user-1", "client-1",
                Set.of("openid", "profile", "email"),
                Duration.ofMinutes(15));

        assertThat(json)
                .contains("\"iss\":\"https://issuer.example/\"")
                .contains("\"sub\":\"user-1\"")
                .contains("\"aud\":\"client-1\"")
                .contains("\"client_id\":\"client-1\"")
                .contains("\"exp\":" + NOW.plus(Duration.ofMinutes(15)).getEpochSecond())
                .contains("\"iat\":" + NOW.getEpochSecond())
                .containsPattern("\"jti\":\"[A-Za-z0-9_\\-]+\"");
    }

    @Test
    void scopeIsSpaceSeparatedAndAlphabeticallySorted() {
        String json = new AccessTokenBuilder(ISSUER, FIXED).build(
                "user-1", "client-1",
                Set.of("profile", "openid", "email"),
                Duration.ofMinutes(15));

        // Sorted alphabetically -> "email openid profile".
        assertThat(json).contains("\"scope\":\"email openid profile\"");
    }

    @Test
    void emptyScopesYieldsEmptyScopeString() {
        String json = new AccessTokenBuilder(ISSUER, FIXED).build(
                "user-1", "client-1", Set.of(), Duration.ofMinutes(15));

        assertThat(json).contains("\"scope\":\"\"");
    }

    @Test
    void jtiIsPresentAndDifferentBetweenInvocations() {
        AccessTokenBuilder builder = new AccessTokenBuilder(ISSUER, FIXED);
        String a = builder.build("user-1", "client-1", Set.of("openid"), Duration.ofMinutes(15));
        String b = builder.build("user-1", "client-1", Set.of("openid"), Duration.ofMinutes(15));

        Pattern jtiPattern = Pattern.compile("\"jti\":\"([A-Za-z0-9_\\-]+)\"");
        Matcher ma = jtiPattern.matcher(a);
        Matcher mb = jtiPattern.matcher(b);
        assertThat(ma.find()).isTrue();
        assertThat(mb.find()).isTrue();
        assertThat(ma.group(1)).isNotEqualTo(mb.group(1));
    }

    @Test
    void expEqualsIatPlusLifetime() {
        Duration lifetime = Duration.ofHours(2);
        String json = new AccessTokenBuilder(ISSUER, FIXED).build(
                "user-1", "client-1", Set.of("openid"), lifetime);

        long iat = NOW.getEpochSecond();
        long exp = NOW.plus(lifetime).getEpochSecond();
        assertThat(json).contains("\"iat\":" + iat).contains("\"exp\":" + exp);
        assertThat(exp - iat).isEqualTo(lifetime.toSeconds());
    }

    @Test
    void escapesSpecialCharsInClientId() {
        // Defensive: a client id with reserved JSON chars must still produce
        // parseable JSON. Real client ids should not contain quotes; this
        // pins the encoder's escape behavior.
        String json = new AccessTokenBuilder(ISSUER, FIXED).build(
                "user-1", "tricky\"id", Set.of("openid"), Duration.ofMinutes(15));

        assertThat(json).contains("\"aud\":\"tricky\\\"id\"")
                .contains("\"client_id\":\"tricky\\\"id\"");
    }
}
