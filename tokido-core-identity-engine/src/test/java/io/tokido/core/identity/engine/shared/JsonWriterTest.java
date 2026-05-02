package io.tokido.core.identity.engine.shared;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the wire-shape contract of {@link JsonWriter}. The engine module
 * is Jackson-free; if these tests change, every consumer's wire output
 * changes. Behavioral equivalence with the inlined helpers that
 * previously lived in {@code AuthorizationCodeData}, {@code IdTokenBuilder},
 * and {@code AccessTokenBuilder} is the contract.
 */
class JsonWriterTest {

    @Test
    void appendStringEscapesRfc8259ShortFormChars() {
        StringBuilder sb = new StringBuilder();
        JsonWriter.appendString(sb, "a\"b\\c\bd\fe\nf\rg\th");
        assertThat(sb).hasToString("\"a\\\"b\\\\c\\bd\\fe\\nf\\rg\\th\"");
    }

    @Test
    void appendStringEscapesAsciiControlCharsAsUnicode() {
        StringBuilder sb = new StringBuilder();
        JsonWriter.appendString(sb, "\u0001x\u001fy");
        assertThat(sb).hasToString("\"\\u0001x\\u001fy\"");
    }

    @Test
    void appendStringPassesNonAsciiThrough() {
        // Non-ASCII (>= U+0020) is emitted verbatim - no Unicode escape.
        StringBuilder sb = new StringBuilder();
        JsonWriter.appendString(sb, "café \uD83D\uDE00");
        assertThat(sb).hasToString("\"café \uD83D\uDE00\"");
    }

    @Test
    void appendOptionalStringFieldSkipsNullAndPreservesFirstFlag() {
        StringBuilder sb = new StringBuilder();
        boolean first = JsonWriter.appendOptionalStringField(sb, "k", null, true);
        assertThat(first).isTrue();
        assertThat(sb).isEmpty();

        boolean stillNotFirst = JsonWriter.appendOptionalStringField(sb, "k", null, false);
        assertThat(stillNotFirst).isFalse();
        assertThat(sb).isEmpty();
    }

    @Test
    void appendOptionalStringFieldEmitsLeadingCommaWhenNotFirst() {
        StringBuilder sb = new StringBuilder("{\"a\":\"1\"");
        boolean first = JsonWriter.appendOptionalStringField(sb, "b", "2", false);
        assertThat(first).isFalse();
        assertThat(sb).hasToString("{\"a\":\"1\",\"b\":\"2\"");
    }

    @Test
    void appendOptionalStringFieldOmitsLeadingCommaWhenFirst() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = JsonWriter.appendOptionalStringField(sb, "b", "2", true);
        assertThat(first).isFalse();
        assertThat(sb).hasToString("{\"b\":\"2\"");
    }

    @Test
    void appendRequiredStringFieldAlwaysAppends() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = JsonWriter.appendRequiredStringField(sb, "b", "v", true);
        assertThat(first).isFalse();
        assertThat(sb).hasToString("{\"b\":\"v\"");

        StringBuilder sb2 = new StringBuilder("{\"a\":\"1\"");
        JsonWriter.appendRequiredStringField(sb2, "b", "2", false);
        assertThat(sb2).hasToString("{\"a\":\"1\",\"b\":\"2\"");
    }

    @Test
    void appendNumberFieldEmitsLongCorrectlyForPositiveZeroAndNegative() {
        StringBuilder sb = new StringBuilder();
        JsonWriter.appendNumberField(sb, "exp", 1762086400L, true);
        assertThat(sb).hasToString("\"exp\":1762086400");

        StringBuilder zero = new StringBuilder();
        JsonWriter.appendNumberField(zero, "n", 0L, true);
        assertThat(zero).hasToString("\"n\":0");

        StringBuilder neg = new StringBuilder();
        JsonWriter.appendNumberField(neg, "n", -42L, false);
        assertThat(neg).hasToString(",\"n\":-42");
    }

    @Test
    void appendOptionalStringArrayFieldSkipsEmptySetAndPreservesFirstFlag() {
        StringBuilder sb = new StringBuilder();
        boolean first = JsonWriter.appendOptionalStringArrayField(sb, "scopes", Set.of(), true);
        assertThat(first).isTrue();
        assertThat(sb).isEmpty();
    }

    @Test
    void appendOptionalStringArrayFieldEmitsCommaSeparatedEntries() {
        StringBuilder sb = new StringBuilder("{");
        // LinkedHashSet pins iteration order so the assertion is deterministic.
        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        scopes.add("profile");
        scopes.add("email");
        boolean first = JsonWriter.appendOptionalStringArrayField(sb, "scopes", scopes, true);
        assertThat(first).isFalse();
        assertThat(sb).hasToString("{\"scopes\":[\"openid\",\"profile\",\"email\"]");
    }

    @Test
    void appendOptionalStringArrayFieldEmitsLeadingCommaWhenNotFirst() {
        StringBuilder sb = new StringBuilder("{\"a\":\"1\"");
        Set<String> single = new LinkedHashSet<>();
        single.add("only");
        JsonWriter.appendOptionalStringArrayField(sb, "scopes", single, false);
        assertThat(sb).hasToString("{\"a\":\"1\",\"scopes\":[\"only\"]");
    }
}
