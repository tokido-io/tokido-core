package io.tokido.core.identity.engine.authorize;

import org.apiguardian.api.API;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * The opaque payload an issued authorization code carries until it is
 * redeemed at the token endpoint. Persisted in {@code PersistedGrant.data}
 * as JSON. Public-but-INTERNAL: shared between {@link AuthorizeHandler}
 * (which writes it) and {@code TokenHandler} (which reads it back at /token).
 *
 * <p>Every field is nullable except {@code scopes} and {@code redirectUri};
 * those are required for the token-endpoint redemption to verify and bind
 * the access token. {@code codeChallenge}/{@code codeChallengeMethod} are
 * present when PKCE was used; {@code nonce} when the client supplied one;
 * {@code authTime}/{@code requestedAcr} for ID-token claims.
 *
 * <p>Serialization: manual JSON via {@link #toJson()} / {@link #fromJson(String)}.
 * The engine module is intentionally Jackson-free; most fields are URL-safe
 * Base64 / scope tokens, the few free-form fields ({@code redirectUri},
 * {@code requestedAcr}) are minimally JSON-string-escaped.
 *
 * @param nonce               OIDC nonce; nullable
 * @param codeChallenge       PKCE challenge; nullable
 * @param codeChallengeMethod PKCE method ({@code "S256"} or {@code "plain"}); nullable
 * @param scopes              consented scopes; non-null, may be empty
 * @param redirectUri         redirect URI bound to the code; non-null and non-blank
 * @param authTime            when the user authenticated; nullable
 * @param requestedAcr        ACR requested via {@code acr_values}; nullable
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2.RC1")
public record AuthorizationCodeData(
        String nonce,
        String codeChallenge,
        String codeChallengeMethod,
        Set<String> scopes,
        String redirectUri,
        Instant authTime,
        String requestedAcr) {

    public AuthorizationCodeData {
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        Objects.requireNonNull(redirectUri, "redirectUri");
        if (redirectUri.isBlank()) {
            throw new IllegalArgumentException("redirectUri must not be blank");
        }
    }

    /**
     * @return canonical JSON encoding of this record; null fields are omitted
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder(128);
        sb.append('{');
        boolean first = true;
        first = appendStringField(sb, "nonce", nonce, first);
        first = appendStringField(sb, "codeChallenge", codeChallenge, first);
        first = appendStringField(sb, "codeChallengeMethod", codeChallengeMethod, first);
        first = appendScopes(sb, scopes, first);
        first = appendStringField(sb, "redirectUri", redirectUri, first);
        first = appendStringField(sb, "authTime", authTime == null ? null : authTime.toString(), first);
        appendStringField(sb, "requestedAcr", requestedAcr, first);
        sb.append('}');
        return sb.toString();
    }

    /**
     * Inverse of {@link #toJson()}.
     *
     * @param json canonical JSON (only the shape produced by {@link #toJson()} is supported)
     * @return reconstructed record
     * @throws IllegalArgumentException if the JSON is malformed or required fields are missing
     */
    public static AuthorizationCodeData fromJson(String json) {
        Objects.requireNonNull(json, "json");
        TinyJsonReader r = new TinyJsonReader(json);
        r.expect('{');
        String nonce = null;
        String codeChallenge = null;
        String codeChallengeMethod = null;
        Set<String> scopes = Set.of();
        String redirectUri = null;
        Instant authTime = null;
        String requestedAcr = null;
        if (!r.tryConsume('}')) {
            while (true) {
                String key = r.readString();
                r.expect(':');
                switch (key) {
                    case "nonce" -> nonce = r.readNullableString();
                    case "codeChallenge" -> codeChallenge = r.readNullableString();
                    case "codeChallengeMethod" -> codeChallengeMethod = r.readNullableString();
                    case "scopes" -> scopes = r.readStringArray();
                    case "redirectUri" -> redirectUri = r.readNullableString();
                    case "authTime" -> {
                        String s = r.readNullableString();
                        if (s != null) {
                            try {
                                authTime = Instant.parse(s);
                            } catch (DateTimeParseException e) {
                                throw new IllegalArgumentException("authTime: not ISO-8601: " + s, e);
                            }
                        }
                    }
                    case "requestedAcr" -> requestedAcr = r.readNullableString();
                    default -> r.skipValue();
                }
                if (r.tryConsume(',')) continue;
                r.expect('}');
                break;
            }
        }
        if (redirectUri == null) {
            throw new IllegalArgumentException("redirectUri missing in JSON");
        }
        return new AuthorizationCodeData(
                nonce, codeChallenge, codeChallengeMethod, scopes, redirectUri, authTime, requestedAcr);
    }

    private static boolean appendStringField(StringBuilder sb, String name, String value, boolean first) {
        if (value == null) return first;
        if (!first) sb.append(',');
        sb.append('"').append(name).append("\":");
        appendJsonString(sb, value);
        return false;
    }

    private static boolean appendScopes(StringBuilder sb, Set<String> scopes, boolean first) {
        if (scopes.isEmpty()) return first;
        if (!first) sb.append(',');
        sb.append("\"scopes\":[");
        boolean firstElem = true;
        for (String s : scopes) {
            if (!firstElem) sb.append(',');
            appendJsonString(sb, s);
            firstElem = false;
        }
        sb.append(']');
        return false;
    }

    /** Minimal JSON-string escape: {@code \" \\ \b \f \n \r \t} and ASCII control chars. */
    private static void appendJsonString(StringBuilder sb, String s) {
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
     * Tiny pull-style JSON reader scoped to this class's serialization shape:
     * objects, string/null values, and arrays of strings. Whitespace is
     * skipped; numbers/booleans/nested objects are not used by us but
     * {@link #skipValue()} tolerates strings, nulls, arrays-of-strings,
     * literals, and numbers for forward-compat.
     */
    private static final class TinyJsonReader {
        private final String src;
        private int pos;

        TinyJsonReader(String src) {
            this.src = src;
            this.pos = 0;
        }

        void expect(char c) {
            skipWs();
            if (pos >= src.length() || src.charAt(pos) != c) {
                throw new IllegalArgumentException(
                        "expected '" + c + "' at pos " + pos + " in: " + src);
            }
            pos++;
        }

        boolean tryConsume(char c) {
            skipWs();
            if (pos < src.length() && src.charAt(pos) == c) {
                pos++;
                return true;
            }
            return false;
        }

        /** Reads a JSON string; throws if the next non-ws token is not a string. */
        String readString() {
            skipWs();
            if (pos >= src.length() || src.charAt(pos) != '"') {
                throw new IllegalArgumentException("expected string at pos " + pos + " in: " + src);
            }
            return readQuoted();
        }

        /** Reads a JSON string OR the literal {@code null}. */
        String readNullableString() {
            skipWs();
            if (pos < src.length() && src.charAt(pos) == 'n') {
                expectLiteral("null");
                return null;
            }
            return readString();
        }

        /** Reads a JSON array of strings into an immutable set. */
        Set<String> readStringArray() {
            expect('[');
            LinkedHashSet<String> out = new LinkedHashSet<>();
            if (tryConsume(']')) return Set.copyOf(out);
            while (true) {
                out.add(readString());
                if (tryConsume(',')) continue;
                expect(']');
                break;
            }
            return Set.copyOf(out);
        }

        /**
         * Skip a value of a supported shape: string, {@code null}, or
         * array of strings. Mirrors exactly the shapes we serialize, so a
         * forward-compat field added by a newer engine writer is parseable.
         */
        void skipValue() {
            skipWs();
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected EOF");
            }
            char c = src.charAt(pos);
            if (c == '"') { readQuoted(); return; }
            if (c == 'n') { expectLiteral("null"); return; }
            if (c == '[') { readStringArray(); return; }
            throw new IllegalArgumentException("unsupported token at pos " + pos + ": " + c);
        }

        private void expectLiteral(String lit) {
            skipWs();
            if (pos + lit.length() > src.length()
                    || !src.regionMatches(pos, lit, 0, lit.length())) {
                throw new IllegalArgumentException("expected '" + lit + "' at pos " + pos);
            }
            pos += lit.length();
        }

        /** Caller has verified src.charAt(pos) == '"'. */
        private String readQuoted() {
            pos++; // opening "
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= src.length()) {
                        throw new IllegalArgumentException("unterminated escape");
                    }
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"'  -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/'  -> sb.append('/');
                        case 'b'  -> sb.append('\b');
                        case 'f'  -> sb.append('\f');
                        case 'n'  -> sb.append('\n');
                        case 'r'  -> sb.append('\r');
                        case 't'  -> sb.append('\t');
                        case 'u'  -> {
                            if (pos + 4 > src.length()) {
                                throw new IllegalArgumentException("bad unicode escape");
                            }
                            sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                            pos += 4;
                        }
                        default -> throw new IllegalArgumentException("bad escape \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("unterminated string");
        }

        private void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }
    }
}
