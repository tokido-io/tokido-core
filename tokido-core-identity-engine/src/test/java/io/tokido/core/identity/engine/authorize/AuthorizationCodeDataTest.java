package io.tokido.core.identity.engine.authorize;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Round-trip and shape tests for {@link AuthorizationCodeData} JSON encoding.
 * The engine module is Jackson-free; the encoding is hand-rolled, so these
 * tests pin the format and lock in the null-omission rule.
 */
class AuthorizationCodeDataTest {

    @Test
    void roundTripPreservesAllFields() {
        AuthorizationCodeData orig = new AuthorizationCodeData(
                "n-0S6_WzA2Mj",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "S256",
                Set.of("openid", "profile"),
                "https://app.example/cb",
                Instant.parse("2026-05-02T10:11:12Z"),
                "urn:mace:incommon:iap:silver");

        AuthorizationCodeData round = AuthorizationCodeData.fromJson(orig.toJson());

        assertThat(round).isEqualTo(orig);
    }

    @Test
    void roundTripWithNullOptionalFields() {
        AuthorizationCodeData orig = new AuthorizationCodeData(
                null,
                null,
                null,
                Set.of("openid"),
                "https://app.example/cb",
                null,
                null);

        String json = orig.toJson();

        // Optional fields omitted from JSON when null.
        assertThat(json)
                .doesNotContain("\"nonce\"")
                .doesNotContain("\"codeChallenge\"")
                .doesNotContain("\"codeChallengeMethod\"")
                .doesNotContain("\"authTime\"")
                .doesNotContain("\"requestedAcr\"")
                .contains("\"redirectUri\":\"https://app.example/cb\"")
                .contains("\"scopes\":[\"openid\"]");

        AuthorizationCodeData round = AuthorizationCodeData.fromJson(json);
        assertThat(round).isEqualTo(orig);
    }

    @Test
    void roundTripEscapesSpecialCharsInRedirectUri() {
        // Path with reserved JSON chars (backslash + quote) — exotic, but the encoder
        // must still produce parseable JSON.
        AuthorizationCodeData orig = new AuthorizationCodeData(
                null, null, null,
                Set.of("openid"),
                "https://app.example/cb?weird=\"a\\b\"",
                null, null);

        AuthorizationCodeData round = AuthorizationCodeData.fromJson(orig.toJson());
        assertThat(round.redirectUri()).isEqualTo("https://app.example/cb?weird=\"a\\b\"");
    }

    @Test
    void emptyScopesAreOmittedFromJsonAndRehydrateAsEmptySet() {
        AuthorizationCodeData orig = new AuthorizationCodeData(
                null, null, null, Set.of(), "https://app.example/cb", null, null);

        String json = orig.toJson();
        assertThat(json).doesNotContain("\"scopes\"");

        AuthorizationCodeData round = AuthorizationCodeData.fromJson(json);
        assertThat(round.scopes()).isEmpty();
    }

    @Test
    void instantSerializesAsIso8601() {
        AuthorizationCodeData d = new AuthorizationCodeData(
                null, null, null, Set.of("openid"),
                "https://app.example/cb",
                Instant.parse("2026-05-02T10:11:12Z"),
                null);
        assertThat(d.toJson()).contains("\"authTime\":\"2026-05-02T10:11:12Z\"");
    }

    @Test
    void unknownFieldsAreSkippedByReader() {
        // Forward-compat: a future version of the format may add string,
        // null, or array-of-string fields, and an older engine instance
        // reading a newer payload should not blow up.
        String json = "{\"redirectUri\":\"https://app.example/cb\","
                + "\"scopes\":[\"openid\"],"
                + "\"futureString\":\"some-value\","
                + "\"futureNull\":null,"
                + "\"futureArray\":[\"a\",\"b\"]}";

        AuthorizationCodeData round = AuthorizationCodeData.fromJson(json);
        assertThat(round.redirectUri()).isEqualTo("https://app.example/cb");
        assertThat(round.scopes()).containsExactly("openid");
    }

    @Test
    void rejectsUnsupportedJsonValueShape() {
        // Numbers/booleans/objects in the future would require explicit support;
        // the reader fails fast rather than silently misparsing.
        String json = "{\"redirectUri\":\"https://app.example/cb\","
                + "\"scopes\":[\"openid\"],"
                + "\"futureNumber\":42}";
        assertThatThrownBy(() -> AuthorizationCodeData.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void readsEmptyJsonObject() {
        // Empty object is malformed (missing redirectUri) but the parser must
        // still cleanly recognize the shape and emit a useful error.
        assertThatThrownBy(() -> AuthorizationCodeData.fromJson("{}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redirectUri");
    }

    @Test
    void parserToleratesWhitespace() {
        String json = "{\n  \"redirectUri\" : \"https://app.example/cb\" ,\n"
                + "  \"scopes\" : [ \"openid\" , \"profile\" ]\n}";
        AuthorizationCodeData round = AuthorizationCodeData.fromJson(json);
        assertThat(round.redirectUri()).isEqualTo("https://app.example/cb");
        assertThat(round.scopes()).containsExactlyInAnyOrder("openid", "profile");
    }

    @Test
    void parsesAllJsonStringEscapes() {
        // Hits every escape branch the reader knows about, including the
        // \\uXXXX path (control char 0x01 is emitted by the writer that way).
        String tricky = "\"\\\b\f\n\r\t/" + (char) 0x01;
        AuthorizationCodeData orig = new AuthorizationCodeData(
                tricky, null, null, Set.of("openid"),
                "https://app.example/cb",
                null, null);
        AuthorizationCodeData round = AuthorizationCodeData.fromJson(orig.toJson());
        assertThat(round.nonce()).isEqualTo(tricky);
    }

    @Test
    void parserHandlesEscapedSlashAndUnicode() {
        // Inputs from a different JSON writer might use escaped solidus and
        // hex-escapes; the reader must accept both, even though our writer
        // does not emit them. (Strings built char-by-char to keep the
        // backslash-u sequence out of javac's unicode-escape preprocessor.)
        String backslash = "\\";
        String json = "{\"redirectUri\":\"https:" + backslash + "/" + backslash + "/app.example"
                + backslash + "/cb\",\"nonce\":\"" + backslash + "u0041" + backslash + "u0042\","
                + "\"scopes\":[\"openid\"]}";
        AuthorizationCodeData round = AuthorizationCodeData.fromJson(json);
        assertThat(round.redirectUri()).isEqualTo("https://app.example/cb");
        assertThat(round.nonce()).isEqualTo("AB");
    }

    @Test
    void rejectsJsonWithUnterminatedString() {
        assertThatThrownBy(() -> AuthorizationCodeData.fromJson("{\"redirectUri\":\"unclosed"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsJsonExpectingStringGotNumber() {
        // scopes must be an array of strings; a numeric element fails fast.
        assertThatThrownBy(() -> AuthorizationCodeData.fromJson(
                "{\"redirectUri\":\"https://app.example/cb\",\"scopes\":[1]}"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsJsonWithoutRedirectUri() {
        String json = "{\"scopes\":[\"openid\"]}";
        assertThatThrownBy(() -> AuthorizationCodeData.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redirectUri");
    }

    @Test
    void rejectsBlankRedirectUri() {
        assertThatThrownBy(() -> new AuthorizationCodeData(
                null, null, null, Set.of(), "", null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsMalformedJson() {
        assertThatThrownBy(() -> AuthorizationCodeData.fromJson("not-json"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
