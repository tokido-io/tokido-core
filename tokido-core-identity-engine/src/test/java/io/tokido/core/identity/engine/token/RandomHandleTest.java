package io.tokido.core.identity.engine.token;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link RandomHandle} entropy + URL-safe-Base64 shape.
 */
class RandomHandleTest {

    @Test
    void generatesNonEmptyHandle() {
        assertThat(RandomHandle.generate(32)).isNotBlank();
    }

    @Test
    void thirtyTwoBytesProduces43CharBase64UrlNoPadding() {
        // 32 bytes Base64url no-padding -> ceil(32 * 4 / 3) = 43 chars.
        String handle = RandomHandle.generate(32);
        assertThat(handle).hasSize(43).matches("[A-Za-z0-9_\\-]{43}");
    }

    @Test
    void sixteenBytesProduces22CharBase64UrlNoPadding() {
        // 16 bytes -> ceil(16 * 4 / 3) = 22 chars.
        String handle = RandomHandle.generate(16);
        assertThat(handle).hasSize(22).matches("[A-Za-z0-9_\\-]{22}");
    }

    @Test
    void distinctCallsProduceDistinctHandles() {
        // Collisions for a 32-byte SecureRandom output are statistically
        // impossible; if these match the test passes by chance only.
        String a = RandomHandle.generate(32);
        String b = RandomHandle.generate(32);
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void rejectsNonPositiveByteCount() {
        assertThatThrownBy(() -> RandomHandle.generate(0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RandomHandle.generate(-1))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
