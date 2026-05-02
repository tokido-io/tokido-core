package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;

/**
 * Outcome of a federated authentication via {@code tokido-core-identity-broker}.
 * Passed to {@link UserStore#createFromExternalProvider(BrokeredAuthentication)}
 * so the local {@link User} record can be created or linked.
 *
 * @param providerId      the {@code providerId} from the {@code IdentityProvider} (M3)
 * @param externalSubject the {@code sub} claim from the external IdP
 * @param claims          additional claims received from the IdP
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public record BrokeredAuthentication(String providerId,
                                     String externalSubject,
                                     Map<String, Object> claims) {

    public BrokeredAuthentication {
        Objects.requireNonNull(providerId, "providerId");
        if (providerId.isBlank()) {
            throw new IllegalArgumentException("providerId must not be blank");
        }
        Objects.requireNonNull(externalSubject, "externalSubject");
        if (externalSubject.isBlank()) {
            throw new IllegalArgumentException("externalSubject must not be blank");
        }
        claims = Map.copyOf(Objects.requireNonNull(claims, "claims"));
    }
}
