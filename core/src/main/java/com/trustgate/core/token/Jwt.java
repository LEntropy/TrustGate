package com.trustgate.core.token;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Compact JWS with RS256 only.
 *
 * <p>The verifier never trusts the token's own "alg" header to choose an algorithm: anything
 * other than RS256 is rejected. That closes the classic "alg": "none" bypass and the
 * RS256→HS256 confusion attack, where the public key is abused as an HMAC secret.
 */
public final class Jwt {
    public static final String ALG = "RS256";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    /** Allowed clock difference between the IdP and a service provider. */
    public static final long CLOCK_SKEW_SECONDS = 60;

    @FunctionalInterface
    public interface KeyResolver {
        /** Public key for a key id, or null if unknown. */
        PublicKey resolve(String kid);
    }

    private Jwt() {}

    public static String sign(Map<String, Object> claims, String kid, PrivateKey key) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", ALG);
        header.put("typ", "JWT");
        header.put("kid", kid);
        String signingInput = B64.encodeToString(json(header)) + "." + B64.encodeToString(json(claims));
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(key);
            s.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + B64.encodeToString(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Verifies the signature and returns the claims. Claim checks are a separate step. */
    public static Map<String, Object> verify(String token, KeyResolver keys) throws TokenException {
        if (token == null) throw new TokenException("missing token");
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) throw new TokenException("malformed token");
        Map<String, Object> header = parse(parts[0], "header");
        if (!ALG.equals(header.get("alg"))) {
            throw new TokenException("unexpected alg " + header.get("alg") + " (only RS256 accepted)");
        }
        PublicKey key = header.get("kid") instanceof String kid ? keys.resolve(kid) : null;
        if (key == null) throw new TokenException("unknown signing key " + header.get("kid"));
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(key);
            s.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!s.verify(B64D.decode(parts[2]))) throw new TokenException("bad signature");
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new TokenException("bad signature");
        }
        return parse(parts[1], "payload");
    }

    /** Header and payload without any verification, for display only. */
    public static Map<String, Object> decodeForDisplay(String token, int part) {
        try {
            return parse(token.split("\\.")[part], "part");
        } catch (Exception e) {
            return Map.of();
        }
    }

    /** OpenID Connect ID token checks (Core 1.0, section 3.1.3.7). */
    public static void validateIdToken(Map<String, Object> c, String issuer, String audience,
                                       String nonce, Instant now) throws TokenException {
        requireIssuerAndAudience(c, issuer, audience);
        long t = now.getEpochSecond();
        if (!(c.get("exp") instanceof Number exp) || exp.longValue() + CLOCK_SKEW_SECONDS < t) {
            throw new TokenException("token expired");
        }
        if (!(c.get("iat") instanceof Number iat) || iat.longValue() - CLOCK_SKEW_SECONDS > t) {
            throw new TokenException("token issued in the future");
        }
        if (nonce == null || !nonce.equals(c.get("nonce"))) throw new TokenException("nonce mismatch");
        if (!(c.get("sub") instanceof String)) throw new TokenException("missing sub");
    }

    /** OpenID Connect Back-Channel Logout token checks (section 2.6). */
    public static void validateLogoutToken(Map<String, Object> c, String issuer, String audience,
                                           Instant now) throws TokenException {
        requireIssuerAndAudience(c, issuer, audience);
        if (!(c.get("iat") instanceof Number iat) || Math.abs(iat.longValue() - now.getEpochSecond()) > 300) {
            throw new TokenException("logout token too old");
        }
        if (!(c.get("events") instanceof Map<?, ?> ev) || !ev.containsKey(LOGOUT_EVENT)) {
            throw new TokenException("missing logout event");
        }
        if (c.containsKey("nonce")) throw new TokenException("logout token must not contain nonce");
        if (!(c.get("sid") instanceof String)) throw new TokenException("missing sid");
        if (!(c.get("jti") instanceof String)) throw new TokenException("missing jti");
    }

    public static final String LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private static void requireIssuerAndAudience(Map<String, Object> c, String issuer, String audience)
            throws TokenException {
        if (!issuer.equals(c.get("iss"))) throw new TokenException("wrong issuer " + c.get("iss"));
        Object aud = c.get("aud");
        boolean ok = audience.equals(aud) || (aud instanceof Collection<?> list && list.contains(audience));
        if (!ok) throw new TokenException("token not issued for this client (aud=" + aud + ")");
    }

    public static byte[] json(Object value) {
        try {
            return JSON.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Map<String, Object> parseJson(String json) throws TokenException {
        try {
            return JSON.readValue(json, MAP);
        } catch (IOException e) {
            throw new TokenException("invalid JSON");
        }
    }

    private static Map<String, Object> parse(String b64, String what) throws TokenException {
        try {
            return JSON.readValue(B64D.decode(b64), MAP);
        } catch (IllegalArgumentException | IOException e) {
            throw new TokenException("malformed " + what);
        }
    }
}
