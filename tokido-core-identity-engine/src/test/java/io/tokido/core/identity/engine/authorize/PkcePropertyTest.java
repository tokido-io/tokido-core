package io.tokido.core.identity.engine.authorize;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property tests for {@link Pkce} (RFC 7636).
 *
 * <p>Invariants exercised:
 * <ul>
 *   <li>{@code S256} round-trip: any RFC-7636-legal verifier verifies against the
 *       challenge computed as {@code BASE64URL(SHA256(verifier))} (no padding).</li>
 *   <li>{@code plain} round-trip: any non-empty verifier verifies against itself
 *       under the {@code plain} method.</li>
 *   <li>Mutated challenge fails: flipping a single character of a correct
 *       {@code S256} challenge always rejects (relies on SHA-256
 *       collision-resistance over single-char mutations of small strings).</li>
 * </ul>
 *
 * <p>Lives in the same package as {@link Pkce} for visibility uniformity with
 * the sibling package-private property tests, even though {@code Pkce} itself
 * is now public-but-{@code @API(INTERNAL)}.
 */
class PkcePropertyTest {

    /** {@code Pkce.verify(v, BASE64URL(SHA256(v)), "S256")} is always {@code true}. */
    @Property
    void s256RoundTrip(@ForAll("rfc7636Verifier") String verifier) {
        String challenge = computeS256Challenge(verifier);
        assertThat(Pkce.verify(verifier, challenge, "S256")).isTrue();
    }

    /** {@code Pkce.verify(v, v, "plain")} is always {@code true} for non-empty verifiers. */
    @Property
    void plainRoundTrip(@ForAll("rfc7636Verifier") String verifier) {
        assertThat(Pkce.verify(verifier, verifier, "plain")).isTrue();
    }

    /** Any single-character mutation of a correct {@code S256} challenge rejects. */
    @Property
    void mutatedChallengeFails(
            @ForAll("rfc7636Verifier") String verifier,
            @ForAll @IntRange(min = 0, max = 1000) int positionSeed,
            @ForAll @IntRange(min = 1, max = 25) int shiftSeed) {
        String challenge = computeS256Challenge(verifier);
        int pos = positionSeed % challenge.length();
        char original = challenge.charAt(pos);
        char mutated = mutateBase64UrlChar(original, shiftSeed);
        String mutatedChallenge = challenge.substring(0, pos) + mutated + challenge.substring(pos + 1);
        // Sanity: the mutation must actually change the string.
        assertThat(mutatedChallenge).isNotEqualTo(challenge);
        assertThat(Pkce.verify(verifier, mutatedChallenge, "S256")).isFalse();
    }

    /** RFC 7636 §4.1: verifier chars are {@code [A-Za-z0-9-._~]}; length 43..128. */
    @Provide
    Arbitrary<String> rfc7636Verifier() {
        return Arbitraries.strings()
                .withCharRange('A', 'Z')
                .withCharRange('a', 'z')
                .withCharRange('0', '9')
                .withChars('-', '.', '_', '~')
                .ofMinLength(43)
                .ofMaxLength(128);
    }

    private static String computeS256Challenge(String verifier) {
        try {
            byte[] sha256 = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available", e);
        }
    }

    /**
     * Map {@code original} to a different character within the base64url alphabet
     * ({@code A-Za-z0-9-_}). Guarantees the result is distinct from the input.
     */
    private static char mutateBase64UrlChar(char original, int shift) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int idx = alphabet.indexOf(original);
        // S256 challenges always come from the base64url alphabet, so idx >= 0.
        int newIdx = (idx + shift) % alphabet.length();
        if (newIdx == idx) {
            newIdx = (newIdx + 1) % alphabet.length();
        }
        return alphabet.charAt(newIdx);
    }
}
