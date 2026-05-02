package io.tokido.core.identity.engine.shared;

import org.apiguardian.api.API;

import java.util.Set;

/**
 * Internal JSON encoding utilities shared by engine handlers that emit
 * canonical JSON payloads (authorization-code data blobs, ID tokens,
 * access tokens). The engine module is intentionally Jackson-free; these
 * helpers stay tiny and pinned by builder tests so a future change to
 * escape rules (e.g., adding {@code \}u2028 for ECMA compatibility)
 * lands in one place.
 *
 * <p>Public-but-INTERNAL: visible across engine sub-packages but not
 * part of the supported API surface.
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2.RC1")
public final class JsonWriter {

    private JsonWriter() {}

    /**
     * Append a JSON-string-encoded form of {@code s} (with surrounding
     * quotes, RFC 8259 escapes for {@code " \ \b \f \n \r \t}, and ASCII
     * control characters as {@code \}uXXXX).
     */
    public static void appendString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    /**
     * Append {@code "name":"value"} preceded by a comma if {@code first}
     * is false. If {@code value} is {@code null} the field is skipped.
     *
     * @return the next {@code first} value: {@code false} if the field
     *         was appended, the input {@code first} unchanged if the
     *         value was null and skipped.
     */
    public static boolean appendOptionalStringField(StringBuilder sb, String name, String value, boolean first) {
        if (value == null) return first;
        if (!first) sb.append(',');
        sb.append('"').append(name).append("\":");
        appendString(sb, value);
        return false;
    }

    /**
     * Append {@code "name":"value"} unconditionally (caller-guaranteed
     * non-null). Always emits a leading comma if {@code first} is false.
     *
     * @return {@code false} (the next {@code first} value)
     */
    public static boolean appendRequiredStringField(StringBuilder sb, String name, String value, boolean first) {
        if (!first) sb.append(',');
        sb.append('"').append(name).append("\":");
        appendString(sb, value);
        return false;
    }

    /**
     * Append {@code "name":number} unconditionally. Always emits a
     * leading comma if {@code first} is false. Used for epoch-second
     * timestamps and other numeric claims.
     *
     * @return {@code false} (the next {@code first} value)
     */
    public static boolean appendNumberField(StringBuilder sb, String name, long value, boolean first) {
        if (!first) sb.append(',');
        sb.append('"').append(name).append("\":").append(value);
        return false;
    }

    /**
     * Append {@code "name":["a","b","c"]} from a {@link Set}. Skips when
     * the set is empty. Iteration order follows the set's iterator.
     *
     * @return the next {@code first} value: {@code false} if the field
     *         was appended, the input {@code first} unchanged if the
     *         set was empty and skipped.
     */
    public static boolean appendOptionalStringArrayField(StringBuilder sb, String name, Set<String> values, boolean first) {
        if (values.isEmpty()) return first;
        if (!first) sb.append(',');
        sb.append('"').append(name).append("\":[");
        boolean firstElem = true;
        for (String s : values) {
            if (!firstElem) sb.append(',');
            appendString(sb, s);
            firstElem = false;
        }
        sb.append(']');
        return false;
    }
}
