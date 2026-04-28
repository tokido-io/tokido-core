package io.tokido.core.identity.conformance;

import java.util.ArrayList;
import java.util.List;

/**
 * Brittle, library-free JSON scraping helpers used by {@link OidcConformanceIT}.
 *
 * <p>Why hand-rolled? The conformance module is intentionally dep-light at M0; the OIDF responses
 * are well-known shapes and we do not want to pull in Jackson or another JSON dep that might
 * conflict with the engine module's eventual dependencies. As the suite of fields we extract grows
 * at M2+, revisit this decision.
 *
 * <p><strong>Limitations:</strong>
 * <ul>
 *   <li>Does not handle escaped quotes ({@code \"}) inside string values.</li>
 *   <li>Field name match is naive substring; field names that are substrings of other field names
 *       can produce wrong results. The OIDF API surface is well-defined enough that this hasn't
 *       bitten in practice, but new uses should grep for substring overlap first.</li>
 *   <li>No support for nested object traversal — flat field extraction only.</li>
 * </ul>
 */
final class JsonScrape {

    private JsonScrape() {}

    /**
     * Extract a single string field's value from {@code json}. Throws {@link IllegalStateException}
     * if the field is missing.
     *
     * <p>Implementation moved verbatim from {@code OidcConformanceIT}.
     */
    static String extractStringField(String json, String field) {
        String key = "\"" + field + "\"";
        int idx = json.indexOf(key);
        if (idx < 0) {
            throw new IllegalStateException(
                    "field '" + field + "' missing in JSON: " + json);
        }
        int colon = json.indexOf(':', idx + key.length());
        // Skip whitespace after colon.
        int pos = colon + 1;
        while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) pos++;
        if (pos >= json.length()) {
            throw new IllegalStateException("field '" + field + "' has no value in: " + json);
        }
        if (json.charAt(pos) == '"') {
            int end = json.indexOf('"', pos + 1);
            return json.substring(pos + 1, end);
        }
        // Non-string value (number, boolean) — extract until delimiter.
        int end = pos;
        while (end < json.length()
                && json.charAt(end) != ','
                && json.charAt(end) != '}'
                && json.charAt(end) != ']') {
            end++;
        }
        return json.substring(pos, end).trim();
    }

    /**
     * Like {@link #extractStringField(String, String)} but returns {@code ""} when the field is
     * missing.
     *
     * <p>Implementation moved verbatim from {@code OidcConformanceIT}.
     */
    static String extractStringFieldOrEmpty(String json, String field) {
        try {
            return extractStringField(json, field);
        } catch (IllegalStateException e) {
            return "";
        }
    }

    /**
     * Extract module names from a plan-creation response. Returns an empty list if no modules
     * are found (rather than throwing).
     *
     * <p>Plan JSON shape (confirmed by live probe):
     * <pre>{@code
     * {
     *   "id": "...",
     *   "modules": [
     *     {"testModule": "oidcc-server", "variant": {...}, "instances": []},
     *     {"testModule": "oidcc-userinfo-get", "variant": {...}, "instances": []},
     *     ...
     *   ]
     * }
     * }</pre>
     *
     * <p>Implementation moved verbatim from {@code OidcConformanceIT}.
     */
    static List<String> extractModuleNames(String planJson) {
        List<String> names = new ArrayList<>();
        String key = "\"testModule\"";
        int search = 0;
        while (true) {
            int idx = planJson.indexOf(key, search);
            if (idx < 0) break;
            int colon = planJson.indexOf(':', idx + key.length());
            int q1 = planJson.indexOf('"', colon + 1);
            int q2 = planJson.indexOf('"', q1 + 1);
            names.add(planJson.substring(q1 + 1, q2));
            search = q2 + 1;
        }
        return names;
    }

    /**
     * Count non-overlapping occurrences of {@code needle} in {@code haystack}.
     *
     * <p>Used by status counting. Returns 0 when {@code needle} is absent.
     */
    static long countOccurrences(String haystack, String needle) {
        if (needle.isEmpty()) return 0;
        long count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}
