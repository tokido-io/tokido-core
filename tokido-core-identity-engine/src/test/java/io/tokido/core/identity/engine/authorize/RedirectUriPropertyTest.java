package io.tokido.core.identity.engine.authorize;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property tests for {@link RedirectUriMatcher}.
 *
 * <p>Invariants exercised:
 * <ul>
 *   <li>Any URI present in {@code registered} matches.</li>
 *   <li>Any URI absent from {@code registered} fails to match.</li>
 *   <li>Any single-character mutation of a registered URI fails to match
 *       against the singleton set containing the original — the matcher
 *       enforces exact equality, so mutations cannot collide.</li>
 * </ul>
 *
 * <p>Lives in the same package as {@link RedirectUriMatcher} to keep the
 * matcher package-private (no need to bump API visibility for tests).
 */
class RedirectUriPropertyTest {

    /** Any URI in the registered set is matched. */
    @Property
    void registeredMatches(
            @ForAll("nonEmptyRedirectUriSet") Set<String> registered,
            @ForAll @IntRange(min = 0, max = 1000) int pickSeed) {
        String submitted = pick(registered, pickSeed);
        assertThat(RedirectUriMatcher.matches(submitted, registered)).isTrue();
    }

    /** Any URI not in the registered set fails to match. */
    @Property
    void unregisteredFails(
            @ForAll("redirectUriSet") Set<String> registered,
            @ForAll("redirectUri") String submitted) {
        Assume.that(!registered.contains(submitted));
        assertThat(RedirectUriMatcher.matches(submitted, registered)).isFalse();
    }

    /** A single-character mutation of a registered URI never matches its singleton set. */
    @Property
    void anyMutationFails(
            @ForAll("redirectUri") String original,
            @ForAll @IntRange(min = 0, max = 1000) int positionSeed,
            @ForAll @IntRange(min = 1, max = 25) int shiftSeed) {
        int pos = positionSeed % original.length();
        char originalChar = original.charAt(pos);
        char mutatedChar = mutateUriChar(originalChar, shiftSeed);
        String mutated = original.substring(0, pos) + mutatedChar + original.substring(pos + 1);
        // Sanity: the mutation must change the string. Filter the rare cases where
        // the URI generator already contained the same char at adjacent indexes.
        Assume.that(!mutated.equals(original));
        assertThat(RedirectUriMatcher.matches(mutated, Set.of(original))).isFalse();
    }

    @Provide
    Arbitrary<String> redirectUri() {
        return Arbitraries.strings()
                .withCharRange('a', 'z')
                .withCharRange('A', 'Z')
                .withCharRange('0', '9')
                .withChars('-', '.')
                .ofMinLength(4)
                .ofMaxLength(32)
                .map(s -> "https://" + s + ".example.org/cb");
    }

    @Provide
    Arbitrary<Set<String>> redirectUriSet() {
        return redirectUri().set().ofMinSize(0).ofMaxSize(5);
    }

    @Provide
    Arbitrary<Set<String>> nonEmptyRedirectUriSet() {
        return redirectUri().set().ofMinSize(1).ofMaxSize(5);
    }

    private static String pick(Set<String> set, int seed) {
        int target = Math.floorMod(seed, set.size());
        int i = 0;
        for (String s : set) {
            if (i == target) {
                return s;
            }
            i++;
        }
        throw new IllegalStateException("unreachable");
    }

    /**
     * Map {@code original} to a different printable character that is still
     * URI-safe ({@code [A-Za-z0-9.-]}), guaranteeing the mutation differs.
     */
    private static char mutateUriChar(char original, int shift) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";
        int idx = alphabet.indexOf(original);
        if (idx < 0) {
            // Char from the constant prefix/suffix (e.g. ':', '/'). Force a flip
            // to a known-different alphabet entry.
            return alphabet.charAt(shift % alphabet.length());
        }
        int newIdx = (idx + shift) % alphabet.length();
        if (newIdx == idx) {
            newIdx = (newIdx + 1) % alphabet.length();
        }
        return alphabet.charAt(newIdx);
    }
}
