package com.trustgate.sp;

import com.trustgate.core.web.Web;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
import java.util.Set;

/**
 * Every page needs a local session. Without one the browser is sent to the IdP with fresh
 * `state` (CSRF protection for the callback) and `nonce` (binds the ID token to this login).
 */
public class AuthFilter implements Filter {
    private static final Set<String> PUBLIC = Set.of("/callback", "/backchannel-logout", "/logged-out");
    static final String PENDING = "sp.pending";

    record Pending(String state, String nonce, String returnTo) implements Serializable {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String path = req.getServletPath();
        HttpSession existing = req.getSession(false);
        if (PUBLIC.contains(path) || path.startsWith("/static/")
                || (existing != null && existing.getAttribute(SpUser.ATTR) != null)) {
            chain.doFilter(request, response);
            return;
        }
        Sp sp = Sp.get(req.getServletContext());
        String returnTo = req.getRequestURI() + (req.getQueryString() == null ? "" : "?" + req.getQueryString());
        Pending p = new Pending(Web.randomToken(16), Web.randomToken(16), returnTo);
        req.getSession().setAttribute(PENDING, p);
        resp.sendRedirect(sp.idpPublicUrl + "/authorize?response_type=code"
                + "&client_id=" + Sp.enc(sp.clientId)
                + "&redirect_uri=" + Sp.enc(sp.redirectUri())
                + "&state=" + Sp.enc(p.state())
                + "&nonce=" + Sp.enc(p.nonce()));
    }
}
