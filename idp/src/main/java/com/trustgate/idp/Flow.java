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
    /** IdP page to show after login (a fixed path set by the server, never taken from the request). */
    static final String RETURN_TO = "returnTo";

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

    /**
     * The lock check in /login only covers new logins. A login that passed the password step
     * before the account was locked must not be able to finish (or keep guessing OTP codes),
     * so every second-factor step checks the lock again and abandons the attempt if needed.
     * Returns true when the request was answered with a redirect.
     */
    static boolean abortIfLocked(Idp idp, HttpServletRequest req, HttpServletResponse resp, User u)
            throws IOException {
        if (!u.isLocked(Instant.now())) return false;
        HttpSession s = req.getSession();
        s.removeAttribute(PENDING_USER);
        s.removeAttribute(OTP_ATTEMPTS);
        s.removeAttribute(ENROLL_SECRET);
        idp.audit.log(u.username(), "LOGIN_BLOCKED", "account locked during second factor", Web.clientIp(req));
        s.setAttribute(FLASH, "로그인 실패가 반복되어 계정이 잠겼습니다. 잠시 후 처음부터 다시 로그인해 주세요.");
        resp.sendRedirect(req.getContextPath() + "/login");
        return true;
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
        String returnTo = (String) s.getAttribute(RETURN_TO);
        s.removeAttribute(RETURN_TO);
        if (ar != null) {
            s.removeAttribute(AUTHZ_REQUEST);
            redirectWithCode(idp, req, resp, sso, ar);
        } else {
            resp.sendRedirect(req.getContextPath() + (returnTo != null ? returnTo : "/"));
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
