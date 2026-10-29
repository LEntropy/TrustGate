package com.trustgate.idp;

import com.trustgate.core.db.User;
import com.trustgate.core.web.Web;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/** First factor: username and password, with account lockout. */
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    static final String BAD_CREDENTIALS = "아이디 또는 비밀번호가 올바르지 않습니다.";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        if (Flow.sso(req).isPresent()) {
            resp.sendRedirect(req.getContextPath() + "/");
            return;
        }
        Flow.AuthzRequest ar = (Flow.AuthzRequest) req.getSession().getAttribute(Flow.AUTHZ_REQUEST);
        if (ar != null) req.setAttribute("clientName", idp.clients.get(ar.clientId()).name());
        req.setAttribute("demoMode", idp.demoMode);
        Flow.render(req, resp, "login");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        if (!Web.validCsrf(req)) {
            Flow.error(req, resp, 400, "요청이 만료되었거나 위조되었습니다. 다시 시도해 주세요. (CSRF 토큰 불일치)");
            return;
        }
        String username = trim(req.getParameter("username"));
        String password = req.getParameter("password");
        String ip = Web.clientIp(req);
        Optional<User> found = username.isEmpty() || password == null ? Optional.empty()
                : idp.users.findByUsername(username);

        if (found.isEmpty()) {
            // Spend the same time as a real check so response time does not reveal valid usernames.
            idp.hasher.dummyVerify(password == null ? new char[0] : password.toCharArray());
            idp.audit.log(username, "LOGIN_FAIL", "unknown user", ip);
            fail(req, resp, BAD_CREDENTIALS);
            return;
        }
        User u = found.get();
        if (u.isLocked(Instant.now())) {
            long min = Math.max(1, Duration.between(Instant.now(), u.lockedUntil()).toMinutes() + 1);
            idp.audit.log(username, "LOGIN_BLOCKED", "account locked", ip);
            fail(req, resp, "로그인 실패가 반복되어 계정이 잠겼습니다. 약 " + min + "분 후 다시 시도해 주세요.");
            return;
        }
        if (!idp.hasher.verify(password.toCharArray(), u.passwordHash())) {
            boolean locked = idp.users.recordFailure(u.id(), Idp.MAX_FAILURES, Idp.LOCK_DURATION);
            idp.audit.log(username, locked ? "ACCOUNT_LOCKED" : "LOGIN_FAIL", "bad password", ip);
            fail(req, resp, locked
                    ? "로그인에 " + Idp.MAX_FAILURES + "회 실패하여 계정을 " + Idp.LOCK_DURATION.toMinutes() + "분간 잠갔습니다."
                    : BAD_CREDENTIALS);
            return;
        }

        req.changeSessionId();
        req.getSession().setAttribute(Flow.PENDING_USER, u.id());
        idp.audit.log(username, "PASSWORD_OK", "second factor required", ip);
        resp.sendRedirect(req.getContextPath() + (u.otpEnabled() ? "/otp" : "/otp/enroll"));
    }

    private void fail(HttpServletRequest req, HttpServletResponse resp, String message)
            throws ServletException, IOException {
        req.setAttribute("error", message);
        req.setAttribute("username", trim(req.getParameter("username")));
        doGet(req, resp);
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }
}
