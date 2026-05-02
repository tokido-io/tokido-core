package io.tokido.core.identity.spi;

import org.apiguardian.api.API;

import java.util.Set;

/**
 * Source of user accounts and the local-credential authenticator.
 *
 * <p>Most methods are read-only. {@link #createFromExternalProvider} is the
 * single mutation: it materializes a local {@link User} the first time a
 * federated identity completes broker callback at M3.
 *
 * <p>Thread-safety: implementations must be safe for concurrent reads;
 * the create operation must be atomic per-{@code (providerId, externalSubject)}.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M1")
public interface UserStore {

    /**
     * Look up by subject id.
     *
     * @param subjectId the subject identifier
     * @return the user, or {@code null} if not found
     */
    User findById(String subjectId);

    /**
     * Look up by username.
     *
     * @param username the login username
     * @return the user, or {@code null} if not found
     */
    User findByUsername(String username);

    /**
     * Authenticate a user with a username and a credential. Implementations
     * are responsible for hashing/verifying the credential.
     *
     * @param username   the login username
     * @param credential the submitted credential (typically a password)
     * @return one of the four {@link AuthenticationResult} variants
     */
    AuthenticationResult authenticate(String username, String credential);

    /**
     * Look up an existing federated mapping.
     *
     * @param providerId      the IdP's provider id
     * @param externalSubject the {@code sub} claim from the external IdP
     * @return the linked user, or {@code null} if no link exists
     */
    User findByExternalProvider(String providerId, String externalSubject);

    /**
     * Create or fetch the local {@link User} for a federated identity.
     * Idempotent: calling twice with the same {@code BrokeredAuthentication}
     * returns the same {@link User}.
     *
     * @param brokered the broker callback result
     * @return the local user (newly created or existing)
     */
    User createFromExternalProvider(BrokeredAuthentication brokered);

    /**
     * All claims emitted for this subject in tokens.
     *
     * @param subjectId the subject identifier
     * @return non-null, possibly empty, immutable set
     */
    Set<UserClaim> claims(String subjectId);
}
