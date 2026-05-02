package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.AuthenticationResult;
import io.tokido.core.identity.spi.BrokeredAuthentication;
import io.tokido.core.identity.spi.User;
import io.tokido.core.identity.spi.UserClaim;
import io.tokido.core.identity.spi.UserStore;
import org.apiguardian.api.API;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link UserStore} with PBKDF2 password hashing. Constructor
 * takes raw passwords keyed by username; hashes at construction time.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class MapUserStore implements UserStore {

    private final Map<String, User> bySubjectId;
    private final Map<String, User> byUsername;
    private final Map<String, String> hashedPasswords;
    private final ConcurrentHashMap<String, User> federated;
    private final Map<String, Set<UserClaim>> claimsBySubject;

    public MapUserStore(Set<User> users,
                        Map<String, String> passwords,
                        Map<String, User> federatedMappings,
                        Map<String, Set<UserClaim>> claimsBySubject) {
        Objects.requireNonNull(users, "users");
        Objects.requireNonNull(passwords, "passwords");
        Objects.requireNonNull(federatedMappings, "federatedMappings");
        Objects.requireNonNull(claimsBySubject, "claimsBySubject");

        Map<String, User> bySub = new HashMap<>();
        Map<String, User> byName = new HashMap<>();
        for (User u : users) {
            bySub.put(u.subjectId(), u);
            byName.put(u.username(), u);
        }
        Map<String, String> hashed = new HashMap<>();
        for (Map.Entry<String, String> e : passwords.entrySet()) {
            hashed.put(e.getKey(), Pbkdf2.hash(e.getValue()));
        }
        this.bySubjectId = Map.copyOf(bySub);
        this.byUsername = Map.copyOf(byName);
        this.hashedPasswords = Map.copyOf(hashed);
        this.federated = new ConcurrentHashMap<>(federatedMappings);
        this.claimsBySubject = Map.copyOf(claimsBySubject);
    }

    @Override public User findById(String s) { return bySubjectId.get(s); }
    @Override public User findByUsername(String u) { return byUsername.get(u); }

    @Override
    public AuthenticationResult authenticate(String username, String credential) {
        String stored = hashedPasswords.get(username);
        if (stored == null) return new AuthenticationResult.InvalidCredentials();
        if (!Pbkdf2.verify(credential, stored)) return new AuthenticationResult.InvalidCredentials();
        User u = byUsername.get(username);
        if (u == null) return new AuthenticationResult.InvalidCredentials();
        if (!u.enabled()) return new AuthenticationResult.AccountDisabled();
        return new AuthenticationResult.Success(u);
    }

    @Override
    public User findByExternalProvider(String providerId, String externalSubject) {
        return federated.get(key(providerId, externalSubject));
    }

    @Override
    public User createFromExternalProvider(BrokeredAuthentication b) {
        return federated.computeIfAbsent(key(b.providerId(), b.externalSubject()), k -> {
            String sub = "ext-" + UUID.randomUUID();
            return new User(sub, b.providerId() + ":" + b.externalSubject(), true, Map.of());
        });
    }

    @Override
    public Set<UserClaim> claims(String subjectId) {
        return claimsBySubject.getOrDefault(subjectId, Set.of());
    }

    private static String key(String p, String s) { return p + "|" + s; }
}
