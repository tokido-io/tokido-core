package io.tokido.core.identity.protocol;

import org.apiguardian.api.API;

import java.util.Objects;

/**
 * UserInfo endpoint request (OIDC Core §5.3). Carries the bearer access
 * token submitted in the {@code Authorization} header or as a form
 * parameter; framework adapters parse the HTTP request and pass the token
 * here.
 *
 * @param accessToken the access token; non-null and non-blank
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record UserInfoRequest(String accessToken) {

    public UserInfoRequest {
        Objects.requireNonNull(accessToken, "accessToken");
        if (accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
    }
}
