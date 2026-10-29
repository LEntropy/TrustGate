package com.trustgate.idp;

import com.trustgate.core.db.User;
import com.trustgate.core.web.Web;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Login state machine shared by the servlets.
 *
 * <pre>
 *   /authorize ──(no SSO session)──► /login ──password ok──► /otp or /otp/enroll ──code ok──►
 *        ▲                                                                                │
 *        └──────────── complete(): new session id, SsoSession, code to the client ◄────────┘
 * </pre>
 */
final class Flow {
    static final String PENDING_USER = "pendingUserId";
    static final String AUTHZ_REQUEST = "authzRequest";
    static final String OTP_ATTEMPTS = "otpAttempts";
    static final String ENROLL_SECRET = "enrollSecret";
    static final String FLASH = "flash";

    /** The original /authorize request, resumed after the user has authenticated. */
    record AuthzRequest(String clientId, String redirectUri, String state, String nonce) implements Serializable {}

    private Flow() {}

    static void render(HttpServletRequest req, HttpServletResponse resp, String view)
            throws ServletException, IOException {
        HttpSession s = req.getSession();
        req.setAttribute("csrf", Web.csrfToken(s));
        Object flash = s.getAttribute(FLASH);
        if (flash != null) {
            req.setAttribute("flash", flash);
            s.removeAttribute(FLASH);
        }
        req.getRequestDispatcher("/WEB-INF/jsp/" + view + ".jsp").forward(req, resp);
    }

    static void error(HttpServletRequest req, HttpServletResponse resp, int status, String message)
            throws ServletException, IOException {
        resp.setStatus(status);
        req.setAttribute("message", message);
        render(req, resp, "error");
    }

    static Optional<SsoSession> sso(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        return s == null ? Optional.empty() : Optional.ofNullable((SsoSession) s.getAttribute(SsoSession.ATTR));
    }

    static Optional<User> pendingUser(Idp idp, HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        Long id = s == null ? null : (Long) s.getAttribute(PENDING_USER);
        return id == null ? Optional.empty() : idp.users.findById(id);
    }

    /** Both factors verified: start the SSO session and continue where the user came from. */
    static void complete(Idp idp, HttpServletRequest req, HttpServletResponse resp, User u)
            throws IOException {
        HttpSession s = req.getSession();
        s.removeAttribute(PENDING_USER);
        s.removeAttribute(OTP_ATTEMPTS);
        s.removeAttribute(ENROLL_SECRET);
        req.changeSessionId();  // session fixation defence: new id once authenticated
        SsoSession sso = new SsoSession(u.id(), u.username(), u.displayName(), u.role(), Web.randomToken(16),
                Instant.now().getEpochSecond(), List.of("pwd", "otp"));
        s.setAttribute(SsoSession.ATTR, sso);
        idp.users.resetFailures(u.id());
        idp.audit.log(u.username(), "LOGIN_SUCCESS", "amr=pwd+otp sid=" + sso.sid(), Web.clientIp(req));

        AuthzRequest ar = (AuthzRequest) s.getAttribute(AUTHZ_REQUEST);
        if (ar != null) {
            s.removeAttribute(AUTHZ_REQUEST);
            redirectWithCode(idp, req, resp, sso, ar);
        } else {
            resp.sendRedirect(req.getContextPath() + "/");
        }
    }

    static void redirectWithCode(Idp idp, HttpServletRequest req, HttpServletResponse resp, SsoSession sso,
                                 AuthzRequest ar) throws IOException {
        String code = idp.codes.issue(ar.clientId(), ar.redirectUri(), sso, ar.nonce());
        idp.sso.add(sso.sid(), ar.clientId());
        idp.audit.log(sso.username(), "SSO_CODE_ISSUED", "client=" + ar.clientId(), Web.clientIp(req));
        resp.sendRedirect(ar.redirectUri() + "?code=" + enc(code) + "&state=" + enc(ar.state()));
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
