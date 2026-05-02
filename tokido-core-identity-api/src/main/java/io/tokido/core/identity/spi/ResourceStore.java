package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Set;

/**
 * Source of identity scopes and protected resources.
 *
 * <p>The engine consults this SPI during scope resolution: it filters
 * the {@code scope} parameter on authorize/token requests, and produces the
 * audience/scope claims on issued access tokens.
 *
 * <p>Thread-safety: implementations must be safe for concurrent reads.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface ResourceStore {

    /**
     * Look up an identity scope by name.
     *
     * @param name scope name
     * @return the scope, or {@code null} if not found
     */
    IdentityScope findIdentityScope(String name);

    /**
     * Look up a protected resource by name.
     *
     * @param name resource name (used as access-token audience)
     * @return the resource, or {@code null} if not found
     */
    ProtectedResource findProtectedResource(String name);

    /**
     * All identity scopes whose names appear in {@code names}.
     * Names absent from the store are silently dropped from the result.
     *
     * @param names scope names to look up
     * @return non-null, possibly empty, immutable set
     */
    Set<IdentityScope> findIdentityScopesByName(Set<String> names);

    /**
     * All protected resources whose published scopes intersect {@code scopeNames}.
     * Returns the resources, not the scope subset.
     *
     * @param scopeNames scope names to test against
     * @return non-null, possibly empty, immutable set
     */
    Set<ProtectedResource> findResourcesByScope(Set<String> scopeNames);
}
