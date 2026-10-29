package com.trustgate.idp;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Public keys for verifying IdP tokens. Service providers fetch this instead of sharing a secret. */
@WebServlet("/jwks")
public class JwksServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setHeader("Cache-Control", "public, max-age=300");
        TokenServlet.json(resp, 200, Idp.get(getServletContext()).signing.jwks());
    }
}
