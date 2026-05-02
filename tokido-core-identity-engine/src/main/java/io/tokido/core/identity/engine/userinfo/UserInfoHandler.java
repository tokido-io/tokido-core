package io.tokido.core.identity.engine.userinfo;

import io.tokido.core.identity.engine.TokenVerifier;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.protocol.UserInfoRequest;
import io.tokido.core.identity.protocol.UserInfoResult;
import io.tokido.core.identity.spi.User;
import io.tokido.core.identity.spi.UserStore;
import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;

/**
 * Drives the OIDC UserInfo endpoint (OIDC Core §5.3).
 *
 * <p>Verifies the bearer access token via the {@link TokenVerifier} SPI,
 * extracts the {@code sub} claim, looks the user up via {@link UserStore},
 * and returns {@link UserStore#claims(String)} verbatim. Per OIDC Core
 * §5.3.3, {@link UserInfoResult.Success#subjectId()} MUST equal the
 * {@code sub} claim from the access token.
 *
 * <p>RC1 returns the full claim set; scope-based filtering is a refinement
 * for a later milestone.
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2.RC1")
public final class UserInfoHandler {

    private final TokenVerifier tokenVerifier;
    private final KeyStore keyStore;
    private final UserStore userStore;

    public UserInfoHandler(TokenVerifier tokenVerifier, KeyStore keyStore, UserStore userStore) {
        this.tokenVerifier = Objects.requireNonNull(tokenVerifier, "tokenVerifier");
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
        this.userStore = Objects.requireNonNull(userStore, "userStore");
    }

    public UserInfoResult handle(UserInfoRequest req) {
        Objects.requireNonNull(req, "req");
        Map<String, Object> claims = tokenVerifier.verify(req.accessToken(), keyStore);
        if (claims.isEmpty()) {
            return new UserInfoResult.Error("invalid_token", "access token verification failed");
        }
        Object subObj = claims.get("sub");
        if (!(subObj instanceof String sub) || sub.isBlank()) {
            return new UserInfoResult.Error("invalid_token", "missing or non-string sub");
        }
        User user = userStore.findById(sub);
        if (user == null) {
            return new UserInfoResult.Error("invalid_token", "subject not found");
        }
        return new UserInfoResult.Success(sub, userStore.claims(sub));
    }
}
