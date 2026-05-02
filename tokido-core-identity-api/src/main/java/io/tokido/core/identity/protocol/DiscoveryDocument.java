package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * OIDC discovery / OAuth 2.0 authorization-server metadata. Built by
 * {@code IdentityEngine.discovery()} and consumed at the
 * {@code /.well-known/openid-configuration} endpoint.
 *
 * <p>Mandatory fields are typed; less-common metadata fields live in
 * {@code additionalParameters}, mirroring the JWK pattern.
 *
 * @param issuer                              issuer identifier; non-null
 * @param authorizationEndpoint               authorize endpoint; non-null
 * @param tokenEndpoint                       token endpoint; non-null
 * @param userinfoEndpoint                    userinfo endpoint; nullable (only when supported)
 * @param jwksUri                             JWKS endpoint; non-null
 * @param introspectionEndpoint               introspection endpoint; nullable
 * @param revocationEndpoint                  revocation endpoint; nullable
 * @param endSessionEndpoint                  end-session endpoint; nullable
 * @param responseTypesSupported              non-null
 * @param grantTypesSupported                 non-null
 * @param subjectTypesSupported               non-null
 * @param idTokenSigningAlgValuesSupported    non-null
 * @param scopesSupported                     null becomes empty
 * @param tokenEndpointAuthMethodsSupported   null becomes empty
 * @param claimsSupported                     null becomes empty
 * @param additionalParameters                non-null
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record DiscoveryDocument(
        URI issuer,
        URI authorizationEndpoint,
        URI tokenEndpoint,
        URI userinfoEndpoint,
        URI jwksUri,
        URI introspectionEndpoint,
        URI revocationEndpoint,
        URI endSessionEndpoint,
        Set<String> responseTypesSupported,
        Set<String> grantTypesSupported,
        Set<String> subjectTypesSupported,
        Set<String> idTokenSigningAlgValuesSupported,
        Set<String> scopesSupported,
        Set<String> tokenEndpointAuthMethodsSupported,
        Set<String> claimsSupported,
        Map<String, Object> additionalParameters) {

    public DiscoveryDocument {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint");
        Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        Objects.requireNonNull(jwksUri, "jwksUri");
        responseTypesSupported = Set.copyOf(Objects.requireNonNull(
                responseTypesSupported, "responseTypesSupported"));
        grantTypesSupported = Set.copyOf(Objects.requireNonNull(
                grantTypesSupported, "grantTypesSupported"));
        subjectTypesSupported = Set.copyOf(Objects.requireNonNull(
                subjectTypesSupported, "subjectTypesSupported"));
        idTokenSigningAlgValuesSupported = Set.copyOf(Objects.requireNonNull(
                idTokenSigningAlgValuesSupported, "idTokenSigningAlgValuesSupported"));
        scopesSupported = scopesSupported == null ? Set.of() : Set.copyOf(scopesSupported);
        tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported == null
                ? Set.of() : Set.copyOf(tokenEndpointAuthMethodsSupported);
        claimsSupported = claimsSupported == null ? Set.of() : Set.copyOf(claimsSupported);
        additionalParameters = Map.copyOf(Objects.requireNonNull(
                additionalParameters, "additionalParameters"));
    }
}
