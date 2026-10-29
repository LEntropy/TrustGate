package com.trustgate.idp;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * SSO entry point (OIDC authorization endpoint, code flow).
 *
 * <p>Errors in client_id or redirect_uri are shown on the IdP's own page and never redirected:
 * redirecting to an unregistered URI would make the IdP an open redirector and could leak
 * codes to an attacker. Only exact matches against the registered URI are accepted.
 */
@WebServlet("/authorize")
public class AuthorizeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        String clientId = req.getParameter("client_id");
        String redirectUri = req.getParameter("redirect_uri");
        Idp.Client client = clientId == null ? null : idp.clients.get(clientId);

        if (client == null) {
            idp.audit.log(null, "AUTHZ_REJECTED", "unknown client_id=" + clientId, req.getRemoteAddr());
            Flow.error(req, resp, 400, "등록되지 않은 서비스(client_id)입니다.");
            return;
        }
        if (!client.redirectUri().equals(redirectUri)) {
            idp.audit.log(null, "AUTHZ_REJECTED", "redirect_uri mismatch client=" + clientId + " uri=" + redirectUri,
                    req.getRemoteAddr());
            Flow.error(req, resp, 400, "등록된 redirect_uri와 일치하지 않아 요청을 거부했습니다. (오픈 리다이렉트 방지)");
            return;
        }
        String state = req.getParameter("state");
        String nonce = req.getParameter("nonce");
        if (!"code".equals(req.getParameter("response_type")) || isBlank(state) || isBlank(nonce)) {
            Flow.error(req, resp, 400, "response_type=code, state, nonce가 모두 필요합니다.");
            return;
        }

        Flow.AuthzRequest ar = new Flow.AuthzRequest(clientId, redirectUri, state, nonce);
        Optional<SsoSession> sso = Flow.sso(req);
        if (sso.isPresent()) {
            // Already signed in at the IdP: this is the "single" in single sign-on.
            Flow.redirectWithCode(idp, req, resp, sso.get(), ar);
            return;
        }
        req.getSession().setAttribute(Flow.AUTHZ_REQUEST, ar);
        resp.sendRedirect(req.getContextPath() + "/login");
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank() || s.length() > 512;
    }
}
