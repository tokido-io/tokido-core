package io.tokido.core.identity.engine.token;

import io.tokido.core.identity.engine.shared.JsonWriter;
import org.apiguardian.api.API;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;

/**
 * The opaque payload an issued refresh token carries until it is redeemed
 * at the token endpoint. Persisted in {@code PersistedGrant.data} as JSON.
 *
 * <p>Per OIDC Core §12.1, an ID token issued from a refresh-token grant
 * must preserve the {@code nonce} and {@code auth_time} claims of the
 * original ID token. The refresh-token data carries those values so the
 * refresh path can re-emit them. Both fields are nullable: a token issued
 * without a nonce stays without one, and {@code auth_time} is only present
 * when the original authentication captured it.
 *
 * <p>Serialization is hand-rolled JSON via {@link JsonWriter} (no Jackson
 * in the engine module). Subjectid / clientid / scopes already live on the
 * persisted grant header — no need to round-trip them in the data payload.
 *
 * @param nonce    OIDC {@code nonce} carried from the original auth request; nullable
 * @param authTime when the user authenticated; nullable
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2.RC2")
public record RefreshTokenData(String nonce, Instant authTime) {

    /** @return canonical JSON encoding of this record; null fields are omitted */
    public String toJson() {
        StringBuilder sb = new StringBuilder(64);
        sb.append('{');
        boolean first = JsonWriter.appendOptionalStringField(sb, "nonce", nonce, true);
        if (authTime != null) {
            JsonWriter.appendOptionalStringField(sb, "authTime", authTime.toString(), first);
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Inverse of {@link #toJson()}.
     *
     * @param json canonical JSON; only the shape produced by {@link #toJson()} is supported
     * @return reconstructed record (with both fields nullable; an empty {@code "{}"} is valid)
     * @throws IllegalArgumentException if the JSON is malformed
     */
    public static RefreshTokenData fromJson(String json) {
        Objects.requireNonNull(json, "json");
        Reader r = new Reader(json);
        r.expect('{');
        String nonce = null;
        Instant authTime = null;
        if (!r.tryConsume('}')) {
            while (true) {
                String key = r.readString();
                r.expect(':');
                switch (key) {
                    case "nonce" -> nonce = r.readNullableString();
                    case "authTime" -> {
                        String s = r.readNullableString();
                        if (s != null) {
                            try {
                                authTime = Instant.parse(s);
                            } catch (DateTimeParseException e) {
                                throw new IllegalArgumentException(
                                        "authTime: not ISO-8601: " + s, e);
                            }
                        }
                    }
                    default -> r.skipValue();
                }
                if (r.tryConsume(',')) continue;
                r.expect('}');
                break;
            }
        }
        return new RefreshTokenData(nonce, authTime);
    }

    /**
     * Tiny pull-style JSON reader scoped to this record's serialization
     * shape: objects, string/null values. Mirrors the reader inside
     * {@code AuthorizationCodeData} but without the array-of-strings
     * support that record needs and this one doesn't.
     */
    private static final class Reader {
        private final String src;
        private int pos;

        Reader(String src) {
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

        String readString() {
            skipWs();
            if (pos >= src.length() || src.charAt(pos) != '"') {
                throw new IllegalArgumentException("expected string at pos " + pos + " in: " + src);
            }
            return readQuoted();
        }

        String readNullableString() {
            skipWs();
            if (pos < src.length() && src.charAt(pos) == 'n') {
                if (pos + 4 > src.length() || !src.regionMatches(pos, "null", 0, 4)) {
                    throw new IllegalArgumentException("expected 'null' at pos " + pos);
                }
                pos += 4;
                return null;
            }
            return readString();
        }

        void skipValue() {
            skipWs();
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected EOF");
            }
            char c = src.charAt(pos);
            if (c == '"') { readQuoted(); return; }
            if (c == 'n') { readNullableString(); return; }
            throw new IllegalArgumentException("unsupported token at pos " + pos + ": " + c);
        }

        private String readQuoted() {
            pos++;
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
