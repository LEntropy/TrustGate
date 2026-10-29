package com.trustgate.sp;

import com.trustgate.core.token.Jwt;
import com.trustgate.core.token.SigningKeys;
import com.trustgate.core.token.TokenException;
import com.trustgate.core.web.Web;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * One service provider (OIDC relying party). The same WAR is deployed twice; the context
 * path decides which registered client it is: /portal or /mail.
 */
@WebListener
public class Sp implements ServletContextListener, HttpSessionListener {
    private static final Logger LOG = Logger.getLogger(Sp.class.getName());
    private static final String ATTR = Sp.class.getName();
    static final String SID_ATTR = "sp.sid";

    public String clientId;
    public String name;
    public String secret;
    public String issuer;
    public String idpPublicUrl;
    public String idpInternalUrl;
    public String baseUrl;
    public String otherName;
    public String otherUrl;
    public final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    private final Map<String, PublicKey> jwks = new ConcurrentHashMap<>();
    private volatile long jwksFetchedAt;
    private final Map<String, Set<HttpSession>> sessionsBySid = new ConcurrentHashMap<>();
    private final Map<String, Long> seenLogoutJti = new ConcurrentHashMap<>();

    public static Sp get(ServletContext ctx) {
        return (Sp) ctx.getAttribute(ATTR);
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext ctx = event.getServletContext();
        clientId = ctx.getContextPath().substring(1);
        name = clientId.equals("mail") ? "웹메일" : "사내 포털";
        secret = Web.env("TG_CLIENT_" + clientId.toUpperCase() + "_SECRET", clientId + "-secret-change-me");
        issuer = Web.env("TG_ISSUER", "http://localhost:8080/idp");
        idpPublicUrl = issuer;
        idpInternalUrl = Web.env("TG_IDP_INTERNAL", issuer);
        String spBase = Web.env("TG_SP_BASE", "http://localhost:8080");
        baseUrl = spBase + "/" + clientId;
        String other = clientId.equals("mail") ? "portal" : "mail";
        otherName = other.equals("mail") ? "웹메일" : "사내 포털";
        otherUrl = spBase + "/" + other + "/";
        ctx.setAttribute(ATTR, this);
        LOG.info("TrustGate SP '" + clientId + "' ready, issuer=" + issuer);
    }

    public String redirectUri() {
        return baseUrl + "/callback";
    }

    /** Values the JSPs need (EL reads bean getters, not public fields). */
    public void expose(jakarta.servlet.http.HttpServletRequest req) {
        req.setAttribute("spName", name);
        req.setAttribute("clientId", clientId);
        req.setAttribute("otherName", otherName);
        req.setAttribute("otherUrl", otherUrl);
        req.setAttribute("idpUrl", idpPublicUrl);
    }

    // --- token verification -------------------------------------------------------------------

    /** Signature check against the IdP's published keys (JWKS), refetched when a kid is unknown. */
    public Map<String, Object> verify(String token) throws TokenException {
        return Jwt.verify(token, this::key);
    }

    private PublicKey key(String kid) {
        PublicKey k = jwks.get(kid);
        if (k == null && System.currentTimeMillis() - jwksFetchedAt > 10_000) {
            refreshJwks();
            k = jwks.get(kid);
        }
        return k;
    }

    @SuppressWarnings("unchecked")
    private synchronized void refreshJwks() {
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(idpInternalUrl + "/jwks"))
                    .timeout(Duration.ofSeconds(3)).build(), HttpResponse.BodyHandlers.ofString());
            jwksFetchedAt = System.currentTimeMillis();
            for (Map<String, Object> jwk : (List<Map<String, Object>>) Jwt.parseJson(r.body()).get("keys")) {
                jwks.put((String) jwk.get("kid"), SigningKeys.fromJwk(jwk));
            }
        } catch (Exception e) {
            LOG.warning("JWKS fetch failed: " + e);
        }
    }

    /** True the first time a logout token id is seen; a replayed logout token returns false. */
    public boolean firstUseOfJti(String jti) {
        long now = Instant.now().getEpochSecond();
        seenLogoutJti.values().removeIf(t -> t < now - 600);
        return seenLogoutJti.putIfAbsent(jti, now) == null;
    }

    // --- sessions per IdP sid, for back-channel logout ----------------------------------------

    public void register(String sid, HttpSession session) {
        session.setAttribute(SID_ATTR, sid);
        sessionsBySid.computeIfAbsent(sid, k -> ConcurrentHashMap.newKeySet()).add(session);
    }

    /** Ends every local session that belongs to the IdP session `sid`. Returns how many. */
    public int logoutSid(String sid) {
        Set<HttpSession> sessions = sessionsBySid.remove(sid);
        if (sessions == null) return 0;
        int n = 0;
        for (HttpSession s : sessions) {
            try {
                s.invalidate();
                n++;
            } catch (IllegalStateException alreadyGone) {
                // the user logged out here already
            }
        }
        return n;
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        Object sid = se.getSession().getAttribute(SID_ATTR);
        if (sid != null) {
            Set<HttpSession> set = sessionsBySid.get(sid.toString());
            if (set != null) set.remove(se.getSession());
        }
    }

    public String fetchIdToken(String code) throws IOException, InterruptedException, TokenException {
        String auth = java.util.Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String form = "grant_type=authorization_code&code=" + enc(code) + "&redirect_uri=" + enc(redirectUri());
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(idpInternalUrl + "/token"))
                .timeout(Duration.ofSeconds(5))
                .header("Authorization", "Basic " + auth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        Map<String, Object> body = Jwt.parseJson(r.body());
        if (r.statusCode() != 200 || !(body.get("id_token") instanceof String t)) {
            throw new TokenException("token endpoint returned " + r.statusCode() + " " + body.get("error"));
        }
        return t;
    }

    static String enc(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
