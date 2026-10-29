package com.trustgate.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.trustgate.core.crypto.KeyStoreKekProvider;
import com.trustgate.core.token.Jwt;
import com.trustgate.core.token.SigningKeys;
import com.trustgate.core.token.TokenException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JwtTest {
    @TempDir
    Path dir;

    private SigningKeys keys;
    private Jwt.KeyResolver resolver;
    private final Instant now = Instant.ofEpochSecond(1_800_000_000L);
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    @BeforeEach
    void setUp() {
        var kek = KeyStoreKekProvider.openOrCreate(dir.resolve("kek.p12"), "pw".toCharArray());
        keys = SigningKeys.loadOrCreate(dir.resolve("sign.properties"), kek);
        resolver = kid -> kid.equals(keys.kid()) ? keys.publicKey() : null;
    }

    private Map<String, Object> idClaims() {
        Map<String, Object> c = new HashMap<>();
        c.put("iss", "http://idp");
        c.put("sub", "user1");
        c.put("aud", "portal");
        c.put("iat", now.getEpochSecond());
        c.put("exp", now.getEpochSecond() + 300);
        c.put("nonce", "n-1");
        return c;
    }

    @Test
    @DisplayName("Signed token verifies and passes ID token checks")
    void signAndVerify() throws Exception {
        String t = Jwt.sign(idClaims(), keys.kid(), keys.privateKey());
        Map<String, Object> c = Jwt.verify(t, resolver);
        assertEquals("user1", c.get("sub"));
        assertDoesNotThrow(() -> Jwt.validateIdToken(c, "http://idp", "portal", "n-1", now));
    }

    @Test
    @DisplayName("Signing key survives a restart (stored wrapped by the KEK)")
    void keyPersistence() {
        var kek = KeyStoreKekProvider.openOrCreate(dir.resolve("kek.p12"), "pw".toCharArray());
        SigningKeys again = SigningKeys.loadOrCreate(dir.resolve("sign.properties"), kek);
        assertEquals(keys.kid(), again.kid());
        assertEquals(keys.publicKey(), again.publicKey());
    }

    @Test
    @DisplayName("Changing one claim breaks the signature")
    void tamperedPayload() {
        String t = Jwt.sign(idClaims(), keys.kid(), keys.privateKey());
        String[] p = t.split("\\.");
        String forged = new String(Base64.getUrlDecoder().decode(p[1]), StandardCharsets.UTF_8)
                .replace("\"user1\"", "\"admin\"");
        String token = p[0] + "." + B64.encodeToString(forged.getBytes(StandardCharsets.UTF_8)) + "." + p[2];
        TokenException e = assertThrows(TokenException.class, () -> Jwt.verify(token, resolver));
        assertEquals("bad signature", e.getMessage());
    }

    @Test
    @DisplayName("alg=none attack is rejected")
    void algNone() {
        String header = B64.encodeToString("{\"alg\":\"none\",\"kid\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        String body = B64.encodeToString(Jwt.json(idClaims()));
        TokenException e = assertThrows(TokenException.class, () -> Jwt.verify(header + "." + body + ".", resolver));
        assertTrue(e.getMessage().contains("unexpected alg"));
    }

    @Test
    @DisplayName("RS256→HS256 key confusion attack (public key used as HMAC secret) is rejected")
    void algConfusion() throws Exception {
        String header = B64.encodeToString(("{\"alg\":\"HS256\",\"kid\":\"" + keys.kid() + "\"}")
                .getBytes(StandardCharsets.UTF_8));
        String body = B64.encodeToString(Jwt.json(idClaims()));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keys.publicKey().getEncoded(), "HmacSHA256"));
        String sig = B64.encodeToString(mac.doFinal((header + "." + body).getBytes(StandardCharsets.US_ASCII)));
        assertThrows(TokenException.class, () -> Jwt.verify(header + "." + body + "." + sig, resolver));
    }

    @Test
    @DisplayName("Token signed by another key (unknown kid or forged key) is rejected")
    void foreignKey() throws Exception {
        var kek = KeyStoreKekProvider.openOrCreate(dir.resolve("k2.p12"), "pw".toCharArray());
        SigningKeys attacker = SigningKeys.loadOrCreate(dir.resolve("attacker.properties"), kek);
        String unknownKid = Jwt.sign(idClaims(), "evil", attacker.privateKey());
        assertThrows(TokenException.class, () -> Jwt.verify(unknownKid, resolver));
        String sameKid = Jwt.sign(idClaims(), keys.kid(), attacker.privateKey());
        assertThrows(TokenException.class, () -> Jwt.verify(sameKid, resolver));
    }

    @Test
    @DisplayName("ID token for another client, expired, or with a wrong nonce is rejected")
    void claimChecks() {
        Map<String, Object> c = idClaims();
        assertThrows(TokenException.class, () -> Jwt.validateIdToken(c, "http://idp", "mail", "n-1", now));
        assertThrows(TokenException.class, () -> Jwt.validateIdToken(c, "http://evil", "portal", "n-1", now));
        assertThrows(TokenException.class, () -> Jwt.validateIdToken(c, "http://idp", "portal", "n-2", now));
        assertThrows(TokenException.class,
                () -> Jwt.validateIdToken(c, "http://idp", "portal", "n-1", now.plusSeconds(400)));
        c.put("aud", List.of("portal", "other"));
        assertDoesNotThrow(() -> Jwt.validateIdToken(c, "http://idp", "portal", "n-1", now));
    }

    @Test
    @DisplayName("Logout token must carry the logout event and sid, and no nonce")
    void logoutToken() {
        Map<String, Object> c = new HashMap<>();
        c.put("iss", "http://idp");
        c.put("aud", "portal");
        c.put("iat", now.getEpochSecond());
        c.put("jti", "j1");
        c.put("sid", "s1");
        c.put("events", Map.of(Jwt.LOGOUT_EVENT, Map.of()));
        assertDoesNotThrow(() -> Jwt.validateLogoutToken(c, "http://idp", "portal", now));
        c.put("nonce", "x");
        assertThrows(TokenException.class, () -> Jwt.validateLogoutToken(c, "http://idp", "portal", now));
        c.remove("nonce");
        c.remove("events");
        assertThrows(TokenException.class, () -> Jwt.validateLogoutToken(c, "http://idp", "portal", now));
    }

    @Test
    @DisplayName("JWKS round trip gives back the same public key")
    void jwks() throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = ((List<Map<String, Object>>) keys.jwks().get("keys")).get(0);
        RSAPublicKey parsed = SigningKeys.fromJwk(jwk);
        assertEquals(keys.publicKey().getModulus(), parsed.getModulus());
    }
}
