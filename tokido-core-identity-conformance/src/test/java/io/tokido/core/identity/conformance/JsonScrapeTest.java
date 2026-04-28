package io.tokido.core.identity.conformance;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonScrapeTest {

    // ── extractStringField ────────────────────────────────────────────────────

    @Test
    void extractStringFieldReadsSimpleValue() {
        assertEquals("xyz", JsonScrape.extractStringField("{\"id\":\"xyz\"}", "id"));
    }

    @Test
    void extractStringFieldHandlesWhitespace() {
        assertEquals("xyz", JsonScrape.extractStringField("{ \"id\" : \"xyz\" }", "id"));
    }

    @Test
    void extractStringFieldFindsFieldInLargerObject() {
        String json = "{\"name\":\"foo\",\"id\":\"abc-123\",\"status\":\"FINISHED\"}";
        assertEquals("abc-123", JsonScrape.extractStringField(json, "id"));
    }

    @Test
    void extractStringFieldThrowsWhenMissing() {
        assertThrows(IllegalStateException.class,
                () -> JsonScrape.extractStringField("{\"name\":\"foo\"}", "id"));
    }

    @Test
    void extractStringFieldExtractsNumericValue() {
        // Non-string values (numbers) are also supported — extracted until delimiter.
        assertEquals("42", JsonScrape.extractStringField("{\"count\":42}", "count"));
    }

    @Test
    void extractStringFieldExtractsBooleanValue() {
        assertEquals("true", JsonScrape.extractStringField("{\"active\":true}", "active"));
    }

    // ── extractStringFieldOrEmpty ─────────────────────────────────────────────

    @Test
    void extractStringFieldOrEmptyReturnsEmptyWhenMissing() {
        assertEquals("", JsonScrape.extractStringFieldOrEmpty("{\"name\":\"foo\"}", "id"));
    }

    @Test
    void extractStringFieldOrEmptyReturnsValueWhenPresent() {
        assertEquals("FINISHED",
                JsonScrape.extractStringFieldOrEmpty("{\"status\":\"FINISHED\"}", "status"));
    }

    // ── extractModuleNames ────────────────────────────────────────────────────

    @Test
    void extractModuleNamesReturnsAllModules() {
        String planJson = "{\"id\":\"plan-1\",\"modules\":["
                + "{\"testModule\":\"oidcc-server\",\"instances\":[]},"
                + "{\"testModule\":\"oidcc-codereuse\",\"instances\":[]}"
                + "]}";
        List<String> names = JsonScrape.extractModuleNames(planJson);
        assertEquals(2, names.size());
        assertTrue(names.contains("oidcc-server"));
        assertTrue(names.contains("oidcc-codereuse"));
    }

    @Test
    void extractModuleNamesReturnsEmptyListWhenAbsent() {
        assertEquals(0, JsonScrape.extractModuleNames("{\"id\":\"plan-1\"}").size());
    }

    @Test
    void extractModuleNamesPreservesOrder() {
        String planJson = "{\"modules\":["
                + "{\"testModule\":\"alpha\"},"
                + "{\"testModule\":\"beta\"},"
                + "{\"testModule\":\"gamma\"}"
                + "]}";
        List<String> names = JsonScrape.extractModuleNames(planJson);
        assertEquals(List.of("alpha", "beta", "gamma"), names);
    }

    // ── countOccurrences ──────────────────────────────────────────────────────

    @Test
    void countOccurrencesCountsAll() {
        assertEquals(3, JsonScrape.countOccurrences("abcabcabc", "abc"));
    }

    @Test
    void countOccurrencesReturnsZeroWhenAbsent() {
        assertEquals(0, JsonScrape.countOccurrences("abc", "xyz"));
    }

    @Test
    void countOccurrencesIgnoresOverlap() {
        // "aaa" contains "aa" once when using non-overlapping (advance by needle.length()).
        // This test pins the existing non-overlapping behaviour.
        assertEquals(1, JsonScrape.countOccurrences("aaa", "aa"));
    }

    @Test
    void countOccurrencesHandlesSingleCharNeedle() {
        // "banana" has 3 'a' characters (b-a-n-a-n-a).
        assertEquals(3, JsonScrape.countOccurrences("banana", "a"));
    }

    @Test
    void countOccurrencesEmptyHaystackReturnsZero() {
        assertEquals(0, JsonScrape.countOccurrences("", "abc"));
    }
}
