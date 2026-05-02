package io.tokido.core.identity.engine.authorize;

import org.apiguardian.api.API;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * PKCE verification per RFC 7636. Supports {@code S256} (recommended) and
 * {@code plain} methods. Public-but-INTERNAL: shared between
 * {@link AuthorizeHandler} (which records the challenge) and
 * {@code TokenHandler} (which verifies the verifier at /token).
 */
@API(status = API.Status.INTERNAL, since = "0.1.0-M2.RC1")
public final class Pkce {

    private Pkce() {}

    /**
     * @param verifier  the code_verifier the client presents at /token
     * @param challenge the code_challenge stored from /authorize
     * @param method    {@code "S256"} or {@code "plain"}; null treated as "plain" per RFC 7636 §4.2
     * @return true if the verifier matches the challenge
     */
    public static boolean verify(String verifier, String challenge, String method) {
        if (verifier == null || challenge == null) return false;
        String effective = method == null ? "plain" : method;
        return switch (effective) {
            case "plain" -> verifier.equals(challenge);
            case "S256" -> {
                try {
                    byte[] sha256 = MessageDigest.getInstance("SHA-256")
                            .digest(verifier.getBytes(StandardCharsets.US_ASCII));
                    String computed = Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(sha256);
                    yield computed.equals(challenge);
                } catch (Exception e) {
                    yield false;
                }
            }
            default -> false;
        };
    }
}
