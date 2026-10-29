package com.trustgate.sp;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Redirect target after IdP login. Checks `state`, swaps the code for an ID token over the
 * back channel, verifies signature and claims, then starts a local session.
 */
@WebServlet("/callback")
public class CallbackServlet extends HttpServlet {
    private static final ObjectMapper PRETTY = new ObjectMapper();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Sp sp = Sp.get(getServletContext());
        HttpSession session = req.getSession(false);
        AuthFilter.Pending p = session == null ? null : (AuthFilter.Pending) session.getAttribute(AuthFilter.PENDING);
        if (p == null || !Web.constantEquals(p.state(), req.getParameter("state"))) {
            fail(req, resp, "state 값이 일치하지 않아 로그인 응답을 거부했습니다. (CSRF·로그인 위조 방지)");
            return;
        }
        session.removeAttribute(AuthFilter.PENDING);  // one use per login attempt
        String code = req.getParameter("code");
        if (code == null) {
            fail(req, resp, "IdP가 인가 코드를 보내지 않았습니다: " + req.getParameter("error"));
            return;
        }
        try {
            String idToken = sp.fetchIdToken(code);
            Map<String, Object> claims = sp.verify(idToken);
            Jwt.validateIdToken(claims, sp.issuer, sp.clientId, p.nonce(), Instant.now());

            req.changeSessionId();  // new session id after login (session fixation defence)
            String sid = (String) claims.get("sid");
            SpUser user = new SpUser((String) claims.get("sub"), (String) claims.get("name"), (String) claims.get("role"),
                    sid, ((Number) claims.get("auth_time")).longValue(), (List<?>) claims.get("amr"), idToken,
                    pretty(Jwt.decodeForDisplay(idToken, 0)), pretty(claims), Instant.now().getEpochSecond());
            session.setAttribute(SpUser.ATTR, user);
            sp.register(sid, session);
            String target = p.returnTo().startsWith(req.getContextPath() + "/") ? p.returnTo() : req.getContextPath() + "/";
            resp.sendRedirect(target);
        } catch (TokenException e) {
            fail(req, resp, "ID 토큰 검증 실패: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail(req, resp, "IdP 응답을 기다리다 중단되었습니다.");
        }
    }

    private static String pretty(Map<String, Object> m) throws IOException {
        return PRETTY.writerWithDefaultPrettyPrinter().writeValueAsString(m);
    }

    static void fail(HttpServletRequest req, HttpServletResponse resp, String message)
            throws ServletException, IOException {
        resp.setStatus(400);
        Sp.get(req.getServletContext()).expose(req);
        req.setAttribute("message", message);
        req.getRequestDispatcher("/WEB-INF/jsp/error.jsp").forward(req, resp);
    }
}
