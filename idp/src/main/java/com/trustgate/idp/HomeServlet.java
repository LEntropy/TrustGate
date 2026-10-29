package com.trustgate.idp;

import com.trustgate.core.crypto.Masking;
import com.trustgate.core.db.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/** "My account" page at the IdP. Personal data is decrypted and shown masked only. */
@WebServlet("")
public class HomeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        Optional<SsoSession> sso = Flow.sso(req);
        if (sso.isEmpty()) {
            resp.sendRedirect(req.getContextPath() + "/login");
            return;
        }
        User u = idp.users.findById(sso.get().userId()).orElseThrow();
        req.setAttribute("sso", sso.get());
        req.setAttribute("user", u);
        req.setAttribute("rrn", Masking.rrn(idp.users.rrn(u)));
        req.setAttribute("phone", Masking.phone(idp.users.phone(u)));
        req.setAttribute("email", Masking.email(u.email()));
        req.setAttribute("clients", idp.clients.values());
        req.setAttribute("connected", idp.sso.clients(sso.get().sid()));
        Flow.render(req, resp, "home");
    }
}
