package io.tokido.core.identity.spi;

import io.tokido.core.identity.key.KeyState;
import io.tokido.core.identity.key.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EnumsTest {

    @Test
    void grantTypeEnumeratesSupportedGrants() {
        assertThat(GrantType.values()).contains(
                GrantType.AUTHORIZATION_CODE,
                GrantType.REFRESH_TOKEN,
                GrantType.CLIENT_CREDENTIALS);
    }

    @Test
    void clientAuthenticationMethodEnumeratesRfc6749Methods() {
        assertThat(ClientAuthenticationMethod.values()).contains(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                ClientAuthenticationMethod.NONE);
    }

    @Test
    void refreshTokenUsageHasOneTimeAndReuse() {
        assertThat(RefreshTokenUsage.values()).contains(
                RefreshTokenUsage.ONE_TIME,
                RefreshTokenUsage.REUSE);
    }

    @Test
    void signatureAlgorithmCoversCommonJwsAlgs() {
        assertThat(SignatureAlgorithm.values()).contains(
                SignatureAlgorithm.RS256,
                SignatureAlgorithm.ES256,
                SignatureAlgorithm.EDDSA);
    }

    @Test
    void keyStateHasAtLeastActiveAndRetired() {
        assertThat(KeyState.values()).contains(
                KeyState.ACTIVE,
                KeyState.RETIRED);
    }
}
