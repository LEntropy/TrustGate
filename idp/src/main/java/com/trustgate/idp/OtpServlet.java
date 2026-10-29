package com.trustgate.idp;

import com.trustgate.core.db.User;
import com.trustgate.core.web.Web;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;
import java.util.OptionalLong;

/** Second factor: TOTP code from the user's authenticator app. */
@WebServlet("/otp")
public class OtpServlet extends HttpServlet {
    static final int MAX_ATTEMPTS = 5;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        Optional<User> u = Flow.pendingUser(idp, req);
        if (u.isEmpty() || !u.get().otpEnabled()) {
            resp.sendRedirect(req.getContextPath() + "/login");
            return;
        }
        req.setAttribute("username", u.get().username());
        if (idp.demoMode) req.setAttribute("demoCode", idp.totp.currentCode(idp.users.otpSecret(u.get())));
        Flow.render(req, resp, "otp");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        if (!Web.validCsrf(req)) {
            Flow.error(req, resp, 400, "요청이 만료되었거나 위조되었습니다. (CSRF 토큰 불일치)");
            return;
        }
        Optional<User> pending = Flow.pendingUser(idp, req);
        if (pending.isEmpty() || !pending.get().otpEnabled()) {
            resp.sendRedirect(req.getContextPath() + "/login");
            return;
        }
        User u = pending.get();
        String ip = Web.clientIp(req);
        OptionalLong step = idp.totp.verify(idp.users.otpSecret(u), req.getParameter("code"));

        if (step.isPresent() && idp.users.consumeOtpStep(u.id(), step.getAsLong())) {
            idp.audit.log(u.username(), "OTP_OK", "step=" + step.getAsLong(), ip);
            Flow.complete(idp, req, resp, u);
            return;
        }

        HttpSession s = req.getSession();
        if (step.isPresent()) {
            idp.audit.log(u.username(), "OTP_REPLAY", "step=" + step.getAsLong() + " already used", ip);
            req.setAttribute("error", "이미 사용된 OTP 코드입니다. 다음 코드가 표시될 때까지 기다려 주세요.");
        } else {
            idp.audit.log(u.username(), "OTP_FAIL", "wrong code", ip);
            req.setAttribute("error", "OTP 코드가 올바르지 않습니다.");
        }
        int attempts = (s.getAttribute(Flow.OTP_ATTEMPTS) instanceof Integer n ? n : 0) + 1;
        s.setAttribute(Flow.OTP_ATTEMPTS, attempts);
        boolean locked = idp.users.recordFailure(u.id(), Idp.MAX_FAILURES, Idp.LOCK_DURATION);
        if (locked || attempts >= MAX_ATTEMPTS) {
            // Too many wrong codes: throw away the half-finished login, the password must be entered again.
            s.removeAttribute(Flow.PENDING_USER);
            s.removeAttribute(Flow.OTP_ATTEMPTS);
            idp.audit.log(u.username(), locked ? "ACCOUNT_LOCKED" : "OTP_ABORTED", "too many OTP failures", ip);
            s.setAttribute(Flow.FLASH, locked ? "OTP 인증에 반복 실패하여 계정을 잠갔습니다."
                    : "OTP 인증에 " + MAX_ATTEMPTS + "회 실패했습니다. 처음부터 다시 로그인해 주세요.");
            resp.sendRedirect(req.getContextPath() + "/login");
            return;
        }
        doGet(req, resp);
    }
}
