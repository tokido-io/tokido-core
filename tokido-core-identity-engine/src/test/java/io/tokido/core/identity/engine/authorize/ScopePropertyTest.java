package io.tokido.core.identity.engine.authorize;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Property tests for {@link ScopeFilter}.
 *
 * <p>Invariants exercised:
 * <ul>
 *   <li>If {@code requested ⊆ allowed}, {@code filter} returns the requested set.</li>
 *   <li>If {@code requested} contains any element not in {@code allowed},
 *       {@code filter} throws {@link ScopeFilter.UnsupportedScopeException}.</li>
 *   <li>Empty {@code requested} always passes regardless of {@code allowed}.</li>
 * </ul>
 *
 * <p>Lives in the same package as {@link ScopeFilter} so the package-private
 * helper and exception remain accessible without bumping API visibility.
 */
class ScopePropertyTest {

    /** Any subset of {@code allowed} passes through unchanged. */
    @Property
    void subsetReturnsRequested(
            @ForAll("scopeSet") Set<String> allowed,
            @ForAll long subsetSeed) {
        Set<String> requested = deterministicSubset(allowed, subsetSeed);
        assertThat(ScopeFilter.filter(requested, allowed)).isEqualTo(requested);
    }

    /** A {@code requested} set containing any scope not in {@code allowed} throws. */
    @Property
    void nonSubsetThrows(
            @ForAll("nonEmptyScopeSet") Set<String> allowed,
            @ForAll("scopeName") String extraScope) {
        Assume.that(!allowed.contains(extraScope));
        Set<String> requested = new HashSet<>(allowed);
        requested.add(extraScope);
        assertThatThrownBy(() -> ScopeFilter.filter(requested, allowed))
                .isInstanceOf(ScopeFilter.UnsupportedScopeException.class);
    }

    /** The empty {@code requested} set always passes, even against empty {@code allowed}. */
    @Property
    void emptyRequestedAlwaysPasses(@ForAll("scopeSet") Set<String> allowed) {
        assertThat(ScopeFilter.filter(Set.of(), allowed)).isEmpty();
    }

    @Provide
    Arbitrary<String> scopeName() {
        return Arbitraries.strings().alpha().ofMinLength(3).ofMaxLength(15);
    }

    @Provide
    Arbitrary<Set<String>> scopeSet() {
        return scopeName().set().ofMinSize(0).ofMaxSize(10);
    }

    @Provide
    Arbitrary<Set<String>> nonEmptyScopeSet() {
        return scopeName().set().ofMinSize(1).ofMaxSize(10);
    }

    /**
     * Deterministically derive a subset of {@code source} keyed by {@code seed},
     * so that shrinking remains stable across reruns.
     */
    private static Set<String> deterministicSubset(Set<String> source, long seed) {
        Set<String> out = new HashSet<>();
        long bits = seed;
        for (String element : source) {
            if ((bits & 1L) == 1L) {
                out.add(element);
            }
            bits >>>= 1;
        }
        return out;
    }
}
