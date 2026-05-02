package io.tokido.core.identity.protocol;

import io.tokido.core.identity.spi.UserClaim;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class ResultTypesTest {

    @Test
    void authorizeResultRedirectCopiesParams() {
        AuthorizeResult.Redirect r = new AuthorizeResult.Redirect(
                URI.create("https://app/cb"),
                Map.of("code", "abc"));
        assertThat(r.params()).containsEntry("code", "abc");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> r.params().put("k", "v"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void authorizeResultErrorRequiresNonBlankCode() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new AuthorizeResult.Error("", "desc", "state"));
    }

    @Test
    void authorizeResultMfaRequiredCopiesAcr() {
        AuthorizeResult.MfaRequired m = new AuthorizeResult.MfaRequired(
                Set.of("urn:tokido:acr:mfa"), "state-1");
        assertThat(m.requiredAcr()).containsExactly("urn:tokido:acr:mfa");
    }

    @Test
    void tokenResultSuccessRequiresAccessToken() {
        assertThatNullPointerException().isThrownBy(() ->
                new TokenResult.Success(null, "Bearer", Duration.ofSeconds(60),
                        null, null, Set.of()));
    }

    @Test
    void tokenResultErrorRequiresNonBlankCode() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> new TokenResult.Error("", "desc"));
    }

    @Test
    void userInfoResultSuccessExposesClaims() {
        UserClaim email = new UserClaim("email", "alice@example.com");
        UserInfoResult.Success s = new UserInfoResult.Success("sub-1", Set.of(email));
        assertThat(s.claims()).containsExactly(email);
    }

    @Test
    void introspectionResultActiveExposesScope() {
        IntrospectionResult.Active a = new IntrospectionResult.Active(
                "sub", "client", Set.of("openid"),
                Instant.now().plusSeconds(60), Instant.now(), Map.of());
        assertThat(a.scope()).containsExactly("openid");
    }

    @Test
    void introspectionResultInactiveIsNoArg() {
        assertThat(new IntrospectionResult.Inactive()).isNotNull();
    }

    @Test
    void revocationResultRevokedIsNoArg() {
        assertThat(new RevocationResult.Revoked()).isNotNull();
    }

    @Test
    void endSessionResultDoneIsNoArg() {
        assertThat(new EndSessionResult.Done()).isNotNull();
    }

    @Test
    void authenticationStateAnonymousIsAllNullsAndEmpty() {
        AuthenticationState a = AuthenticationState.anonymous();
        assertThat(a.subjectId()).isNull();
        assertThat(a.authenticatedAt()).isNull();
        assertThat(a.amr()).isEmpty();
        assertThat(a.acr()).isNull();
        assertThat(a.session()).isEmpty();
    }

    @Test
    void authenticationStateNullCollectionsBecomeEmpty() {
        AuthenticationState a = new AuthenticationState("sub", Instant.now(), null, null, null);
        assertThat(a.amr()).isEmpty();
        assertThat(a.session()).isEmpty();
    }

    @Test
    void authorizeResultLoginRequiredIsConstructable() {
        AuthorizeResult.LoginRequired lr = new AuthorizeResult.LoginRequired("max_age");
        assertThat(lr.reason()).isEqualTo("max_age");
    }

    @Test
    void authorizeResultConsentRequiredCopiesScopes() {
        AuthorizeResult.ConsentRequired cr = new AuthorizeResult.ConsentRequired(
                Set.of("profile", "email"), "s1");
        assertThat(cr.requestedScopes()).containsExactlyInAnyOrder("profile", "email");
        assertThat(cr.state()).isEqualTo("s1");
    }

    @Test
    void tokenResultSuccessExposesFields() {
        TokenResult.Success s = new TokenResult.Success(
                "at", "Bearer", Duration.ofSeconds(3600), "rt", "idt", Set.of("openid"));
        assertThat(s.accessToken()).isEqualTo("at");
        assertThat(s.tokenType()).isEqualTo("Bearer");
        assertThat(s.expiresIn()).isEqualTo(Duration.ofSeconds(3600));
        assertThat(s.refreshToken()).isEqualTo("rt");
        assertThat(s.idToken()).isEqualTo("idt");
        assertThat(s.scope()).containsExactly("openid");
    }

    @Test
    void userInfoResultErrorRequiresCode() {
        assertThatNullPointerException().isThrownBy(
                () -> new UserInfoResult.Error(null, "desc"));
        UserInfoResult.Error e = new UserInfoResult.Error("invalid_token", null);
        assertThat(e.code()).isEqualTo("invalid_token");
    }

    @Test
    void revocationResultErrorRequiresCode() {
        assertThatNullPointerException().isThrownBy(
                () -> new RevocationResult.Error(null, "desc"));
        RevocationResult.Error e = new RevocationResult.Error("unsupported_token_type", null);
        assertThat(e.code()).isEqualTo("unsupported_token_type");
    }

    @Test
    void endSessionResultRedirectCopiesParams() {
        EndSessionResult.Redirect r = new EndSessionResult.Redirect(
                URI.create("https://app/logout"), Map.of("state", "xyz"));
        assertThat(r.redirectUri()).isEqualTo(URI.create("https://app/logout"));
        assertThat(r.params()).containsEntry("state", "xyz");
    }

    @Test
    void endSessionResultErrorRequiresCode() {
        assertThatNullPointerException().isThrownBy(
                () -> new EndSessionResult.Error(null, "desc"));
        EndSessionResult.Error e = new EndSessionResult.Error("invalid_request", "bad");
        assertThat(e.code()).isEqualTo("invalid_request");
    }
}
