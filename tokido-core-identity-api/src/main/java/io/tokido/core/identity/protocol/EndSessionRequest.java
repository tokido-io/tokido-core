package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

/**
 * OIDC end-session (logout) request (OIDC Session Mgmt §5).
 *
 * <p>{@code idTokenHint} and {@code postLogoutRedirectUri} are both nullable
 * per spec; engine validates {@code idTokenHint} shape when present.
 *
 * @param idTokenHint           optional ID token hint; nullable
 * @param postLogoutRedirectUri optional post-logout redirect URI; nullable
 * @param state                 optional state echoed back; nullable
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record EndSessionRequest(String idTokenHint, String postLogoutRedirectUri, String state) {
    // All fields nullable; no validation here.
}
