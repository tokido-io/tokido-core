package io.tokido.core.identity.jwt;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.tokido.core.identity.engine.TokenVerifier;
import io.tokido.core.identity.key.KeyStore;
import io.tokido.core.identity.key.SigningKey;
import org.apiguardian.api.API;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Nimbus JOSE+JWT-backed {@link TokenVerifier}.
 *
 * <p>Parses the supplied compact JWS, looks up a matching {@link SigningKey}
 * in the {@link KeyStore} by {@code kid} (both ACTIVE and RETIRED keys are
 * eligible per ADR-0007), verifies the signature using a Nimbus
 * {@link JWSVerifier}, then checks the {@code exp} and {@code nbf} temporal
 * claims if present.
 *
 * <p>Supported algorithms: {@link io.tokido.core.identity.key.SignatureAlgorithm#RS256},
 * {@link io.tokido.core.identity.key.SignatureAlgorithm#ES256},
 * {@link io.tokido.core.identity.key.SignatureAlgorithm#EDDSA} (Ed25519).
 *
 * <p>Public-key derivation (the {@link SigningKey} carries private material;
 * verification needs the public-key components):
 * <ul>
 *   <li>RS256: PKCS#8 → {@link RSAPrivateCrtKey}; modulus and public exponent
 *       are reused to build the {@link RSAPublicKey}.</li>
 *   <li>ES256: PKCS#8 → {@link ECPrivateKey}; the public point is computed by
 *       multiplying the curve generator by the private scalar (P-256 only).</li>
 *   <li>EDDSA: OctetKeyPair JSON → public JWK.</li>
 * </ul>
 *
 * <p>On any error during steps 1–7 (parse, kid lookup, signature, exp, nbf)
 * the returned map is empty. This implementation never throws.
 */
@API(status = API.Status.STABLE, since = "0.1.0-M2.RC1")
public final class NimbusTokenVerifier implements TokenVerifier {

    private final Clock clock;

    /** Creates a verifier using {@link Clock#systemUTC()}. */
    public NimbusTokenVerifier() {
        this(Clock.systemUTC());
    }

    /**
     * Creates a verifier with the supplied clock; useful in tests with a
     * fixed clock so the {@code exp} / {@code nbf} branches are deterministic.
     *
     * @param clock the clock to use for temporal-claim checks; non-null
     */
    public NimbusTokenVerifier(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Map<String, Object> verify(String compactJws, KeyStore keyStore) {
        if (compactJws == null || keyStore == null) {
            return Map.of();
        }
        JWSObject jws;
        try {
            jws = JWSObject.parse(compactJws);
        } catch (java.text.ParseException e) {
            return Map.of();
        }
        String kid = jws.getHeader().getKeyID();
        if (kid == null || kid.isBlank()) {
            return Map.of();
        }
        SigningKey match = null;
        for (SigningKey k : keyStore.allKeys()) {
            if (kid.equals(k.kid())) {
                match = k;
                break;
            }
        }
        if (match == null) {
            return Map.of();
        }
        JWSVerifier verifier;
        try {
            verifier = nimbusVerifier(match);
        } catch (Exception e) {
            return Map.of();
        }
        try {
            if (!jws.verify(verifier)) {
                return Map.of();
            }
        } catch (Exception e) {
            return Map.of();
        }
        Map<String, Object> claims = jws.getPayload().toJSONObject();
        if (claims == null) {
            return Map.of();
        }
        Instant now = clock.instant();
        Object exp = claims.get("exp");
        if (exp instanceof Number n && now.getEpochSecond() >= n.longValue()) {
            return Map.of();
        }
        Object nbf = claims.get("nbf");
        if (nbf instanceof Number n && now.getEpochSecond() < n.longValue()) {
            return Map.of();
        }
        return claims;
    }

    private static JWSVerifier nimbusVerifier(SigningKey key) throws Exception {
        byte[] bytes = key.material().bytes();
        return switch (key.alg()) {
            case RS256 -> {
                RSAPrivateCrtKey priv = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(bytes));
                RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
                yield new RSASSAVerifier(pub);
            }
            case ES256 -> {
                ECPrivateKey priv = (ECPrivateKey) KeyFactory.getInstance("EC")
                        .generatePrivate(new PKCS8EncodedKeySpec(bytes));
                ECParameterSpec params = priv.getParams();
                ECPoint pubPoint = scalarMultiply(priv.getS(), params.getGenerator(), params);
                ECPublicKey pub = (ECPublicKey) KeyFactory.getInstance("EC")
                        .generatePublic(new ECPublicKeySpec(pubPoint, params));
                yield new ECDSAVerifier(pub);
            }
            case EDDSA -> {
                OctetKeyPair okp = OctetKeyPair.parse(new String(bytes, StandardCharsets.UTF_8));
                yield new Ed25519Verifier(okp.toPublicJWK());
            }
        };
    }

    /**
     * Compute {@code k * G} on a short-Weierstrass prime-field curve. Used to
     * derive the EC public point from a private scalar so verification can
     * proceed when the {@link SigningKey} carries only PKCS#8 private bytes.
     *
     * <p>This implementation is non-constant-time but operates on server-side
     * trusted private material owned by the engine; no attacker controls the
     * scalar input on the verification path.
     */
    private static ECPoint scalarMultiply(BigInteger scalar, ECPoint g, ECParameterSpec params) {
        EllipticCurve curve = params.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger a = curve.getA();
        BigInteger n = scalar.mod(params.getOrder());
        ECPoint result = ECPoint.POINT_INFINITY;
        ECPoint addend = g;
        for (int i = 0; i < n.bitLength(); i++) {
            if (n.testBit(i)) {
                result = pointAdd(result, addend, p, a);
            }
            addend = pointDouble(addend, p, a);
        }
        return result;
    }

    private static ECPoint pointAdd(ECPoint p1, ECPoint p2, BigInteger p, BigInteger a) {
        if (p1.equals(ECPoint.POINT_INFINITY)) return p2;
        if (p2.equals(ECPoint.POINT_INFINITY)) return p1;
        BigInteger x1 = p1.getAffineX(), y1 = p1.getAffineY();
        BigInteger x2 = p2.getAffineX(), y2 = p2.getAffineY();
        if (x1.equals(x2)) {
            if (y1.equals(y2)) return pointDouble(p1, p, a);
            return ECPoint.POINT_INFINITY;
        }
        BigInteger lambda = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
        BigInteger x3 = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        return new ECPoint(x3, y3);
    }

    private static ECPoint pointDouble(ECPoint pt, BigInteger p, BigInteger a) {
        if (pt.equals(ECPoint.POINT_INFINITY)) return pt;
        BigInteger x = pt.getAffineX(), y = pt.getAffineY();
        if (y.signum() == 0) return ECPoint.POINT_INFINITY;
        BigInteger three = BigInteger.valueOf(3);
        BigInteger two = BigInteger.valueOf(2);
        BigInteger lambda = three.multiply(x).multiply(x).add(a)
                .multiply(two.multiply(y).modInverse(p)).mod(p);
        BigInteger x3 = lambda.multiply(lambda).subtract(two.multiply(x)).mod(p);
        BigInteger y3 = lambda.multiply(x.subtract(x3)).subtract(y).mod(p);
        return new ECPoint(x3, y3);
    }
}
