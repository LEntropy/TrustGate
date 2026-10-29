package com.trustgate.idp;

import com.trustgate.core.token.Jwt;
import com.trustgate.core.token.TokenException;
import com.trustgate.core.web.Web;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Single logout. Ends the IdP session and tells every service provider that received a token
 * for it, server to server (OIDC Back-Channel Logout), so their sessions end too even if the
 * user never visits them again.
 *
 * <p>Logging out changes state, so a plain cross-site link must not be able to trigger it
 * (logout CSRF). A GET request is accepted only from a service provider that proves the
 * request is about this session with an {@code id_token_hint} it received for it (OIDC
 * RP-Initiated Logout); anything else gets a confirmation page that posts with a CSRF token.
 */
@WebServlet("/logout")
public class LogoutServlet extends HttpServlet {
    public record Result(String client, String name, boolean ok, String detail) {}

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        Optional<SsoSession> sso = Flow.sso(req);
        if (sso.isPresent() && !validHint(idp, req, sso.get())) {
            req.setAttribute("clientId", req.getParameter("client_id"));
            req.setAttribute("postLogoutRedirectUri", req.getParameter("post_logout_redirect_uri"));
            Flow.render(req, resp, "logout_confirm");
            return;
        }
        logout(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (!Web.validCsrf(req)) {
            Flow.error(req, resp, 400, "요청이 만료되었거나 위조되었습니다. (CSRF 토큰 불일치)");
            return;
        }
        logout(req, resp);
    }

    /**
     * The hint must be an ID token this IdP signed for the named client and for the current SSO
     * session. Expiry is not checked: an expired ID token still identifies the session (OIDC
     * RP-Initiated Logout 1.0, section 2).
     */
    private static boolean validHint(Idp idp, HttpServletRequest req, SsoSession sso) {
        String hint = req.getParameter("id_token_hint");
        String clientId = req.getParameter("client_id");
        if (hint == null || clientId == null) return false;
        try {
            Map<String, Object> c = Jwt.verify(hint, kid -> kid.equals(idp.signing.kid()) ? idp.signing.publicKey() : null);
            return idp.issuer.equals(c.get("iss")) && clientId.equals(c.get("aud")) && sso.sid().equals(c.get("sid"));
        } catch (TokenException e) {
            return false;
        }
    }

    private void logout(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        Optional<SsoSession> sso = Flow.sso(req);
        List<Result> results = new ArrayList<>();
        if (sso.isPresent()) {
            SsoSession s = sso.get();
            for (String clientId : idp.sso.remove(s.sid())) {
                results.add(notify(idp, idp.clients.get(clientId), s));
            }
            idp.audit.log(s.username(), "LOGOUT", "sid=" + s.sid() + " notified=" + results.size(), Web.clientIp(req));
        }
        HttpSession session = req.getSession(false);
        if (session != null) session.invalidate();

        Idp.Client client = idp.clients.get(String.valueOf(req.getParameter("client_id")));
        String redirect = req.getParameter("post_logout_redirect_uri");
        if (client != null && client.postLogoutRedirectUri().equals(redirect)) {
            resp.sendRedirect(redirect);
            return;
        }
        req.setAttribute("results", results);
        req.setAttribute("clients", idp.clients.values());
        Flow.render(req, resp, "logged_out");
    }

    private static Result notify(Idp idp, Idp.Client client, SsoSession s) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", idp.issuer);
        claims.put("aud", client.id());
        claims.put("iat", Instant.now().getEpochSecond());
        claims.put("jti", Web.randomToken(16));
        claims.put("sid", s.sid());
        claims.put("events", Map.of(Jwt.LOGOUT_EVENT, Map.of()));
        String token = Jwt.sign(claims, idp.signing.kid(), idp.signing.privateKey());
        try {
            HttpRequest r = HttpRequest.newBuilder(URI.create(client.backchannelLogoutUri()))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("logout_token=" + Flow.enc(token)))
                    .build();
            HttpResponse<String> res = idp.http.send(r, HttpResponse.BodyHandlers.ofString());
            boolean ok = res.statusCode() == 200;
            idp.audit.log(s.username(), ok ? "BACKCHANNEL_LOGOUT_OK" : "BACKCHANNEL_LOGOUT_FAIL",
                    "client=" + client.id() + " status=" + res.statusCode(), null);
            return new Result(client.id(), client.name(), ok, "HTTP " + res.statusCode() + " " + res.body());
        } catch (IOException | InterruptedException e) {
            idp.audit.log(s.username(), "BACKCHANNEL_LOGOUT_FAIL", "client=" + client.id() + " " + e, null);
            return new Result(client.id(), client.name(), false, e.getClass().getSimpleName());
        }
    }
}
