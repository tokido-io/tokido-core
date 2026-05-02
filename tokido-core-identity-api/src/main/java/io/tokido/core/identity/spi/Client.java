package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An OAuth/OIDC client registration.
 *
 * <p>All collection-valued fields are defensively copied to immutable form
 * inside the canonical constructor. Implementations of {@link ClientStore}
 * are not required to preserve insertion order of any set.
 *
 * @param clientId                 unique client identifier; non-null and non-blank
 * @param secrets                  hashed client secrets (any may match); non-null, possibly empty for public clients
 * @param redirectUris             registered redirect URIs (exact match)
 * @param postLogoutRedirectUris   registered post-logout redirect URIs
 * @param allowedScopes            scopes this client may request
 * @param allowedGrantTypes        grant types this client may use
 * @param tokenEndpointAuthMethods permitted client-authn methods at the token endpoint
 * @param requirePkce              if true, authorize requests without PKCE are rejected
 * @param allowOfflineAccess       if true, "offline_access" scope is granted on consent
 * @param accessTokenLifetime      lifetime of access tokens issued to this client
 * @param refreshTokenLifetime     lifetime of refresh tokens issued to this client
 * @param refreshTokenUsage        {@link RefreshTokenUsage#ONE_TIME} or {@link RefreshTokenUsage#REUSE}
 * @param claims                   additional client metadata (read-only key/value)
 * @param enabled                  if false, all flows for this client are rejected
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record Client(
        String clientId,
        Set<ClientSecret> secrets,
        Set<String> redirectUris,
        Set<String> postLogoutRedirectUris,
        Set<String> allowedScopes,
        Set<GrantType> allowedGrantTypes,
        Set<ClientAuthenticationMethod> tokenEndpointAuthMethods,
        boolean requirePkce,
        boolean allowOfflineAccess,
        Duration accessTokenLifetime,
        Duration refreshTokenLifetime,
        RefreshTokenUsage refreshTokenUsage,
        Map<String, String> claims,
        boolean enabled) {

    public Client {
        Objects.requireNonNull(clientId, "clientId");
        if (clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        secrets = Set.copyOf(Objects.requireNonNull(secrets, "secrets"));
        redirectUris = Set.copyOf(Objects.requireNonNull(redirectUris, "redirectUris"));
        postLogoutRedirectUris =
                Set.copyOf(Objects.requireNonNull(postLogoutRedirectUris, "postLogoutRedirectUris"));
        allowedScopes = Set.copyOf(Objects.requireNonNull(allowedScopes, "allowedScopes"));
        allowedGrantTypes =
                Set.copyOf(Objects.requireNonNull(allowedGrantTypes, "allowedGrantTypes"));
        tokenEndpointAuthMethods =
                Set.copyOf(Objects.requireNonNull(tokenEndpointAuthMethods, "tokenEndpointAuthMethods"));
        Objects.requireNonNull(accessTokenLifetime, "accessTokenLifetime");
        Objects.requireNonNull(refreshTokenLifetime, "refreshTokenLifetime");
        Objects.requireNonNull(refreshTokenUsage, "refreshTokenUsage");
        claims = Map.copyOf(Objects.requireNonNull(claims, "claims"));
    }
}
