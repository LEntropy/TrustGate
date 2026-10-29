package com.trustgate.sp;

import com.trustgate.core.token.Jwt;
import com.trustgate.core.token.TokenException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Receives the IdP's signed logout token (OIDC Back-Channel Logout 1.0) and ends every local
 * session of that SSO session. Unsigned, foreign, stale or replayed tokens are rejected, so
 * nobody else can log users out by posting here.
 */
@WebServlet("/backchannel-logout")
public class BackchannelLogoutServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger(BackchannelLogoutServlet.class.getName());

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Sp sp = Sp.get(getServletContext());
        resp.setContentType("text/plain;charset=UTF-8");
        try {
            Map<String, Object> claims = sp.verify(req.getParameter("logout_token"));
            Jwt.validateLogoutToken(claims, sp.issuer, sp.clientId, Instant.now());
            if (!sp.firstUseOfJti((String) claims.get("jti"))) throw new TokenException("replayed logout token");
            int n = sp.logoutSid((String) claims.get("sid"));
            LOG.info("back-channel logout sid=" + claims.get("sid") + " sessions=" + n);
            resp.getWriter().write("sessions ended: " + n);
        } catch (TokenException e) {
            LOG.warning("rejected logout token: " + e.getMessage());
            resp.setStatus(400);
            resp.getWriter().write("invalid logout token");
        }
    }
}
