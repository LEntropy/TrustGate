package com.trustgate.core.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Small helpers shared by the IdP and the service providers. */
public final class Web {
    public static final String CSRF_ATTR = "csrf";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Web() {}

    public static String randomToken(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Per-session CSRF token (synchronizer token pattern), exposed to JSPs as ${csrf}. */
    public static String csrfToken(HttpSession session) {
        String t = (String) session.getAttribute(CSRF_ATTR);
        if (t == null) {
            t = randomToken(24);
            session.setAttribute(CSRF_ATTR, t);
        }
        return t;
    }

    public static boolean validCsrf(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        if (s == null) return false;
        return constantEquals((String) s.getAttribute(CSRF_ATTR), req.getParameter("csrf"));
    }

    public static boolean constantEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    public static String clientIp(HttpServletRequest req) {
        return req.getRemoteAddr();
    }

    public static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
