package com.trustgate.sp;

import com.trustgate.core.web.Web;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

/** Home page, local logout (POST with CSRF token) and the page shown after logout. */
@WebServlet({"", "/logout", "/logged-out"})
public class PagesServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Sp sp = Sp.get(getServletContext());
        sp.expose(req);
        if (req.getServletPath().equals("/logged-out")) {
            req.getRequestDispatcher("/WEB-INF/jsp/logged_out.jsp").forward(req, resp);
            return;
        }
        if (req.getServletPath().equals("/logout")) {
            resp.sendError(405);
            return;
        }
        req.setAttribute("csrf", Web.csrfToken(req.getSession()));
        req.getRequestDispatcher("/WEB-INF/jsp/index.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!req.getServletPath().equals("/logout") || !Web.validCsrf(req)) {
            resp.sendError(400);
            return;
        }
        Sp sp = Sp.get(getServletContext());
        HttpSession s = req.getSession(false);
        if (s != null) s.invalidate();
        // Then end the IdP session, which notifies the other services over the back channel.
        resp.sendRedirect(sp.idpPublicUrl + "/logout?client_id=" + Sp.enc(sp.clientId)
                + "&post_logout_redirect_uri=" + Sp.enc(sp.baseUrl + "/logged-out"));
    }
}
