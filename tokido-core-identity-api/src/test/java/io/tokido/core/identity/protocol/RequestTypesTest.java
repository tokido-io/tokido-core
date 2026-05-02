package io.tokido.core.identity.protocol;

import io.tokido.core.identity.spi.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class RequestTypesTest {

    @Test
    void authorizeRequestRejectsNullClientId() {
        assertThatNullPointerException().isThrownBy(() ->
                new AuthorizeRequest(null, "code", "https://app/cb",
                        Set.of("openid"), "state-1", null, null, null,
                        null, Set.of(), null, null, null, null, Map.of()));
    }

    @Test
    void authorizeRequestRejectsBlankClientId() {
        assertThatIllegalArgumentException().isThrownBy(() ->
                new AuthorizeRequest("", "code", "https://app/cb",
                        Set.of("openid"), "state-1", null, null, null,
                        null, Set.of(), null, null, null, null, Map.of()));
    }

    @Test
    void authorizeRequestNullCollectionsBecomeEmpty() {
        AuthorizeRequest r = new AuthorizeRequest("client-1", "code", null,
                null, null, null, null, null, null, null, null, null, null, null, null);
        assertThat(r.scopes()).isEmpty();
        assertThat(r.acrValues()).isEmpty();
        assertThat(r.additional()).isEmpty();
    }

    @Test
    void tokenRequestExposesAllFields() {
        TokenRequest req = new TokenRequest(
                "authorization_code", "client-1", "secret",
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                "code-1", "https://app/cb", "verifier-1",
                null, Set.of("openid"), Map.of());
        assertThat(req.grantType()).isEqualTo("authorization_code");
        assertThat(req.clientId()).isEqualTo("client-1");
        assertThat(req.code()).isEqualTo("code-1");
    }

    @Test
    void tokenRequestRejectsBlankGrantType() {
        assertThatIllegalArgumentException().isThrownBy(() ->
                new TokenRequest("", "c", null, ClientAuthenticationMethod.NONE,
                        null, null, null, null, Set.of(), Map.of()));
    }

    @Test
    void userInfoRequestRejectsBlankAccessToken() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new UserInfoRequest(""));
    }

    @Test
    void introspectionRequestRejectsBlankToken() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new IntrospectionRequest("", null, "client"));
    }

    @Test
    void revocationRequestRejectsBlankToken() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new RevocationRequest("", null, "client"));
    }

    @Test
    void endSessionRequestAcceptsAllNulls() {
        EndSessionRequest r = new EndSessionRequest(null, null, null);
        assertThat(r.idTokenHint()).isNull();
        assertThat(r.postLogoutRedirectUri()).isNull();
        assertThat(r.state()).isNull();
    }
}
