package io.tokido.core.identity.engine.token;

import io.tokido.core.identity.engine.shared.JsonWriter;
import io.tokido.core.identity.spi.IdentityScope;
import io.tokido.core.identity.spi.ResourceStore;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.identity.spi.UserStore;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Builds the JSON payload of an OIDC ID token per OIDC Core §2.
 *
 * <p>Required claims:
 * <ul>
 *   <li>{@code iss} — issuer URL</li>
 *   <li>{@code sub} — user subject id</li>
 *   <li>{@code aud} — client id (string form)</li>
 *   <li>{@code exp}, {@code iat} — epoch seconds</li>
 * </ul>
 * <p>Conditional claims:
 * <ul>
 *   <li>{@code auth_time} — emitted when {@code authTime} is non-null
 *       (RC1 always emits when available; per OIDC Core, required only for
 *       {@code prompt=login}/{@code max_age} or when the client has
 *       {@code requireAuthTime} set)</li>
 *   <li>{@code nonce} — echoed when present in the captured request</li>
 *   <li>userinfo claims — for each granted scope, the matching
 *       {@link IdentityScope#userClaimNames()} pull values from
 *       {@link UserStore#claims(String)}</li>
 * </ul>
 *
 * <p>The nonce and auth_time values are sourced from the originating
 * authorization request at the auth-code grant path, and from the
 * persisted {@link RefreshTokenData} payload at the refresh-token grant
 * path — preserving them across refreshes per OIDC Core §12.1.</li>
 *
 * <p>RC1 simplification: every {@link UserClaim#value()} is encoded as a JSON
 * string, even if the textual content looks like a number or boolean. M3 will
 * introduce typed claim emission.
 */
final class IdTokenBuilder {

    private final URI issuer;
    private final ResourceStore resourceStore;
    private final UserStore userStore;
    private final Clock clock;
    private final Duration idTokenLifetime;

    IdTokenBuilder(URI issuer,
                   ResourceStore resourceStore,
                   UserStore userStore,
                   Clock clock,
                   Duration idTokenLifetime) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.resourceStore = Objects.requireNonNull(resourceStore, "resourceStore");
        this.userStore = Objects.requireNonNull(userStore, "userStore");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.idTokenLifetime = Objects.requireNonNull(idTokenLifetime, "idTokenLifetime");
    }

    /**
     * Build the JSON body of an ID token.
     *
     * @param subjectId     subject the token is issued to; non-null
     * @param clientId      audience client id; non-null
     * @param grantedScopes scopes that drive userinfo-claim emission; non-null
     * @param nonce         {@code nonce} claim, omitted when null
     * @param authTime      {@code auth_time} claim, omitted when null
     * @return JSON string ready for {@code TokenSigner.sign}
     */
    String build(String subjectId,
                 String clientId,
                 Set<String> grantedScopes,
                 String nonce,
                 Instant authTime) {
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(grantedScopes, "grantedScopes");

        Instant now = clock.instant();
        long iat = now.getEpochSecond();
        long exp = now.plus(idTokenLifetime).getEpochSecond();

        // 1. Determine the union of claim names unlocked by the granted scopes.
        Set<String> unlockedClaimNames = new HashSet<>();
        for (String scope : grantedScopes) {
            IdentityScope identityScope = resourceStore.findIdentityScope(scope);
            if (identityScope == null) continue;
            unlockedClaimNames.addAll(identityScope.userClaimNames());
        }

        // 2. Build a (claim-name -> claim-value) map from the user's claims,
        // filtered by the unlocked set. UserStore.claims() returns a Set with
        // unspecified iteration order, so when multiple UserClaim entries
        // share the same type the surviving value is non-deterministic across
        // runs. RC1 contract is single-valued claims (one value per type);
        // multi-valued claims arrive at M3 and will need a different shape.
        Map<String, String> claimValues = new LinkedHashMap<>();
        if (!unlockedClaimNames.isEmpty()) {
            for (UserClaim claim : userStore.claims(subjectId)) {
                if (unlockedClaimNames.contains(claim.type())) {
                    claimValues.put(claim.type(), claim.value());
                }
            }
        }

        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        boolean first = true;
        first = JsonWriter.appendRequiredStringField(sb, "iss", issuer.toString(), first);
        first = JsonWriter.appendRequiredStringField(sb, "sub", subjectId, first);
        first = JsonWriter.appendRequiredStringField(sb, "aud", clientId, first);
        first = JsonWriter.appendNumberField(sb, "exp", exp, first);
        first = JsonWriter.appendNumberField(sb, "iat", iat, first);
        if (authTime != null) {
            first = JsonWriter.appendNumberField(sb, "auth_time", authTime.getEpochSecond(), first);
        }
        if (nonce != null) {
            first = JsonWriter.appendRequiredStringField(sb, "nonce", nonce, first);
        }
        for (Map.Entry<String, String> e : claimValues.entrySet()) {
            // RC1: every claim emitted as a JSON string. M3 may introduce
            // typed (number/boolean/object) emission.
            first = JsonWriter.appendRequiredStringField(sb, e.getKey(), e.getValue(), first);
        }
        sb.append('}');
        return sb.toString();
    }
}
