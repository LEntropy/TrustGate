package com.trustgate.idp;

import com.trustgate.core.web.Web;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Short-lived, single-use authorization codes. A code is bound to the client and
 * redirect URI it was issued for, and removing it on first use makes a second
 * redemption (code replay) fail.
 */
public final class AuthCodeStore {
    public static final long TTL_SECONDS = 60;

    public record Grant(String clientId, String redirectUri, SsoSession session, String nonce, Instant expiresAt) {}

    private final Map<String, Grant> codes = new ConcurrentHashMap<>();

    public String issue(String clientId, String redirectUri, SsoSession session, String nonce) {
        purgeExpired();
        String code = Web.randomToken(32);
        codes.put(code, new Grant(clientId, redirectUri, session, nonce, Instant.now().plusSeconds(TTL_SECONDS)));
        return code;
    }

    /** Returns the grant and deletes it atomically, or null if unknown, used or expired. */
    public Grant redeem(String code) {
        if (code == null) return null;
        Grant g = codes.remove(code);
        if (g == null || g.expiresAt().isBefore(Instant.now())) return null;
        return g;
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        codes.values().removeIf(g -> g.expiresAt().isBefore(now));
    }
}
