package io.tokido.core;

import java.util.Map;

/**
 * A secret loaded from a {@link io.tokido.core.spi.SecretStore}, together with its metadata.
 *
 * @param secret   the raw secret bytes (may be empty for factors like recovery codes that store data only in metadata)
 * @param metadata factor-specific metadata (e.g., lastCounter for replay protection, hashed backup codes)
 */
public record StoredSecret(byte[] secret, Map<String, Object> metadata) {
}
