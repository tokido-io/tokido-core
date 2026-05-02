package io.tokido.core.identity.engine.token;

import io.tokido.core.identity.engine.shared.JsonWriter;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Builds the JSON payload of a JWT access token per RFC 9068.
 *
 * <p>Emits the required body claims; the JWS header (including
 * {@code typ: at+jwt}) is the {@link io.tokido.core.identity.engine.TokenSigner}'s
 * concern. The builder is stateless and reusable.
 *
 * <p>Required claims emitted:
 * <ul>
 *   <li>{@code iss} — the issuer URL</li>
 *   <li>{@code sub} — the user's subject id</li>
 *   <li>{@code aud} — the client id (RC1 simplification — strictly
 *       RFC 9068 wants the resource server URL, but no resource → audience
 *       wiring exists yet)</li>
 *   <li>{@code client_id} — the client id</li>
 *   <li>{@code scope} — space-separated, alphabetically sorted</li>
 *   <li>{@code exp} — epoch seconds at lifetime expiry</li>
 *   <li>{@code iat} — epoch seconds at issuance</li>
 *   <li>{@code jti} — random 16-byte URL-safe Base64 handle</li>
 * </ul>
 */
final class AccessTokenBuilder {

    /** Entropy of the {@code jti} claim — 16 bytes Base64url no padding → 22 chars. */
    private static final int JTI_BYTE_LENGTH = 16;

    private final URI issuer;
    private final Clock clock;

    AccessTokenBuilder(URI issuer, Clock clock) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Build the JSON body of an access token.
     *
     * @param subjectId     subject the token is issued to; non-null
     * @param clientId      client the token is issued to; non-null
     * @param grantedScopes scopes granted; non-null, possibly empty
     * @param lifetime      access-token lifetime; non-null
     * @return JSON string ready for {@code TokenSigner.sign}
     */
    String build(String subjectId, String clientId, Set<String> grantedScopes, Duration lifetime) {
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(grantedScopes, "grantedScopes");
        Objects.requireNonNull(lifetime, "lifetime");

        Instant now = clock.instant();
        long iat = now.getEpochSecond();
        long exp = now.plus(lifetime).getEpochSecond();
        String jti = RandomHandle.generate(JTI_BYTE_LENGTH);

        List<String> sortedScopes = new ArrayList<>(grantedScopes);
        Collections.sort(sortedScopes);
        String scope = String.join(" ", sortedScopes);

        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        boolean first = true;
        first = JsonWriter.appendRequiredStringField(sb, "iss", issuer.toString(), first);
        first = JsonWriter.appendRequiredStringField(sb, "sub", subjectId, first);
        first = JsonWriter.appendRequiredStringField(sb, "aud", clientId, first);
        first = JsonWriter.appendRequiredStringField(sb, "client_id", clientId, first);
        first = JsonWriter.appendRequiredStringField(sb, "scope", scope, first);
        first = JsonWriter.appendNumberField(sb, "exp", exp, first);
        first = JsonWriter.appendNumberField(sb, "iat", iat, first);
        JsonWriter.appendRequiredStringField(sb, "jti", jti, first);
        sb.append('}');
        return sb.toString();
    }
}
