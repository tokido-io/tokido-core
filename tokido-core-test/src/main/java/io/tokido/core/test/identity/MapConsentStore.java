package io.tokido.core.test.identity;

import io.tokido.core.identity.spi.Consent;
import io.tokido.core.identity.spi.ConsentStore;
import org.apiguardian.api.API;

import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link ConsentStore}. Key: {@code "subjectId|clientId"}. */
@API(status = API.Status.STABLE, since = "0.1.0-M2")
public final class MapConsentStore implements ConsentStore {

    private final ConcurrentHashMap<String, Consent> backing = new ConcurrentHashMap<>();

    private static String key(String s, String c) { return s + "|" + c; }

    @Override public Consent find(String s, String c) { return backing.get(key(s, c)); }
    @Override public void store(Consent consent) {
        backing.put(key(consent.subjectId(), consent.clientId()), consent);
    }
    @Override public void remove(String s, String c) { backing.remove(key(s, c)); }
}
