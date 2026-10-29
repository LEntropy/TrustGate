package com.trustgate.idp;

import com.trustgate.core.token.Jwt;
import com.trustgate.core.web.Web;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Back-channel code exchange (OIDC token endpoint). Called server-to-server by a service
 * provider, never by the browser, so the ID token does not pass through the URL bar or
 * browser history. The client authenticates with its secret.
 */
@WebServlet("/token")
public class TokenServlet extends HttpServlet {
    public static final long ID_TOKEN_TTL = 300;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Idp idp = Idp.get(getServletContext());
        resp.setHeader("Pragma", "no-cache");
        String[] creds = clientCredentials(req);
        Idp.Client client = creds[0] == null ? null : idp.clients.get(creds[0]);
        if (client == null || !Web.constantEquals(client.secret(), creds[1])) {
            idp.audit.log(null, "TOKEN_REJECTED", "client authentication failed id=" + creds[0], req.getRemoteAddr());
            json(resp, 401, Map.of("error", "invalid_client"));
            return;
        }
        if (!"authorization_code".equals(req.getParameter("grant_type"))) {
            json(resp, 400, Map.of("error", "unsupported_grant_type"));
            return;
        }
        AuthCodeStore.Grant g = idp.codes.redeem(req.getParameter("code"));
        if (g == null || !g.clientId().equals(client.id()) || !g.redirectUri().equals(req.getParameter("redirect_uri"))) {
            idp.audit.log(null, "TOKEN_REJECTED", "invalid, expired or reused code client=" + client.id(),
                    req.getRemoteAddr());
            json(resp, 400, Map.of("error", "invalid_grant"));
            return;
        }

        SsoSession s = g.session();
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", idp.issuer);
        claims.put("sub", s.username());
        claims.put("aud", client.id());
        claims.put("iat", now);
        claims.put("exp", now + ID_TOKEN_TTL);
        claims.put("auth_time", s.authTime());
        claims.put("nonce", g.nonce());
        claims.put("sid", s.sid());
        claims.put("amr", s.amr());
        claims.put("name", s.name());
        claims.put("role", s.role());
        String idToken = Jwt.sign(claims, idp.signing.kid(), idp.signing.privateKey());
        idp.audit.log(s.username(), "TOKEN_ISSUED", "client=" + client.id() + " sid=" + s.sid(), req.getRemoteAddr());
        json(resp, 200, Map.of("id_token", idToken, "token_type", "Bearer", "expires_in", ID_TOKEN_TTL));
    }

    /** client_secret_basic (Authorization header) or client_secret_post (form fields). */
    private static String[] clientCredentials(HttpServletRequest req) {
        String auth = req.getHeader("Authorization");
        if (auth != null && auth.startsWith("Basic ")) {
            try {
                String decoded = new String(Base64.getDecoder().decode(auth.substring(6)), StandardCharsets.UTF_8);
                int colon = decoded.indexOf(':');
                if (colon > 0) return new String[] {decoded.substring(0, colon), decoded.substring(colon + 1)};
            } catch (IllegalArgumentException ignored) {
                // fall through to form parameters
            }
        }
        return new String[] {req.getParameter("client_id"), req.getParameter("client_secret")};
    }

    static void json(HttpServletResponse resp, int status, Object body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json;charset=UTF-8");
        resp.getOutputStream().write(Jwt.json(body));
    }
}
