package io.tokido.core.identity.engine.token;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * JSON round-trip tests for {@link RefreshTokenData}. Pins the wire shape
 * of the {@code PersistedGrant.data} payload that refresh tokens carry —
 * see ADR-0008 / OIDC Core §12.1. Hand-rolled JSON, no Jackson.
 */
class RefreshTokenDataTest {

    @Test
    void roundTripWithBothFieldsSet() {
        RefreshTokenData original = new RefreshTokenData(
                "n-abc",
                Instant.parse("2026-05-04T17:30:00Z"));
        String json = original.toJson();
        assertThat(json)
                .contains("\"nonce\":\"n-abc\"")
                .contains("\"authTime\":\"2026-05-04T17:30:00Z\"");

        RefreshTokenData decoded = RefreshTokenData.fromJson(json);
        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void omitsNullNonceFromJson() {
        RefreshTokenData data = new RefreshTokenData(null, Instant.parse("2026-05-04T17:30:00Z"));
        String json = data.toJson();
        assertThat(json).doesNotContain("\"nonce\"");
        assertThat(RefreshTokenData.fromJson(json)).isEqualTo(data);
    }

    @Test
    void omitsNullAuthTimeFromJson() {
        RefreshTokenData data = new RefreshTokenData("n-1", null);
        String json = data.toJson();
        assertThat(json).doesNotContain("\"authTime\"");
        assertThat(RefreshTokenData.fromJson(json)).isEqualTo(data);
    }

    @Test
    void emptyDataRoundTripsToEmptyObject() {
        RefreshTokenData data = new RefreshTokenData(null, null);
        String json = data.toJson();
        assertThat(json).isEqualTo("{}");
        assertThat(RefreshTokenData.fromJson(json)).isEqualTo(data);
    }

    @Test
    void escapesSpecialCharsInNonce() {
        RefreshTokenData data = new RefreshTokenData("nonce \"with\" quotes\nnewline", null);
        String json = data.toJson();
        assertThat(json).contains("\\\"with\\\"").contains("\\n");
        assertThat(RefreshTokenData.fromJson(json)).isEqualTo(data);
    }

    @Test
    void rejectsMalformedJson() {
        assertThatThrownBy(() -> RefreshTokenData.fromJson("{nonce:foo}"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonIso8601AuthTime() {
        assertThatThrownBy(() -> RefreshTokenData.fromJson("{\"authTime\":\"yesterday\"}"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unknownFieldsAreIgnoredForwardCompat() {
        // Future fields added to the data payload must be tolerated by
        // older readers — supports rolling upgrades.
        String json = "{\"nonce\":\"n-1\",\"futureField\":\"whatever\",\"authTime\":\"2026-05-04T17:30:00Z\"}";
        RefreshTokenData decoded = RefreshTokenData.fromJson(json);
        assertThat(decoded.nonce()).isEqualTo("n-1");
        assertThat(decoded.authTime()).isEqualTo(Instant.parse("2026-05-04T17:30:00Z"));
    }

    @Test
    void rejectsMissingValue() {
        assertThatThrownBy(() -> RefreshTokenData.fromJson("{\"nonce\":}"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsUnsupportedJsonValueShape() {
        // A future contributor adding a numeric/array/object field must
        // explicitly extend the reader; silent acceptance would mask
        // forward-compat bugs.
        assertThatThrownBy(() -> RefreshTokenData.fromJson("{\"counter\":42}"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
