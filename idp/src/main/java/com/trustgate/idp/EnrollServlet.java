package com.trustgate.idp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.trustgate.core.crypto.Base32;
import com.trustgate.core.crypto.Totp;
import com.trustgate.core.db.User;
import com.trustgate.core.web.Web;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * First-time OTP registration. The new secret lives only in the session until the user
 * proves the authenticator app works by entering a valid code; then it is stored encrypted.
 */
@WebServlet("/otp/enroll")
public class EnrollServlet extends HttpServlet {
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        Optional<User> u = Flow.pendingUser(idp, req);
        if (u.isEmpty() || u.get().otpEnabled()) {
            resp.sendRedirect(req.getContextPath() + "/login");
            return;
        }
        HttpSession s = req.getSession();
        byte[] secret = (byte[]) s.getAttribute(Flow.ENROLL_SECRET);
        if (secret == null) {
            secret = Totp.newSecret(RANDOM);
            s.setAttribute(Flow.ENROLL_SECRET, secret);
        }
        String uri = Totp.provisioningUri("TrustGate", u.get().username(), secret);
        req.setAttribute("username", u.get().username());
        req.setAttribute("secret", Base32.encode(secret).replaceAll("(.{4})", "$1 ").trim());
        req.setAttribute("qr", qrDataUri(uri));
        if (idp.demoMode) req.setAttribute("demoCode", idp.totp.currentCode(secret));
        Flow.render(req, resp, "enroll");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        if (!Web.validCsrf(req)) {
            Flow.error(req, resp, 400, "요청이 만료되었거나 위조되었습니다. (CSRF 토큰 불일치)");
            return;
        }
        Optional<User> pending = Flow.pendingUser(idp, req);
        byte[] secret = (byte[]) req.getSession().getAttribute(Flow.ENROLL_SECRET);
        if (pending.isEmpty() || pending.get().otpEnabled() || secret == null) {
            resp.sendRedirect(req.getContextPath() + "/login");
            return;
        }
        User u = pending.get();
        OptionalLong step = idp.totp.verify(secret, req.getParameter("code"));
        if (step.isEmpty()) {
            idp.audit.log(u.username(), "OTP_ENROLL_FAIL", "wrong code", Web.clientIp(req));
            req.setAttribute("error", "코드가 맞지 않습니다. 앱에 표시된 6자리 숫자를 입력해 주세요.");
            doGet(req, resp);
            return;
        }
        idp.users.enableOtp(u.id(), secret);
        idp.users.consumeOtpStep(u.id(), step.getAsLong());
        idp.audit.log(u.username(), "OTP_ENROLLED", "TOTP secret stored encrypted", Web.clientIp(req));
        Flow.complete(idp, req, resp, idp.users.findById(u.id()).orElseThrow());
    }

    /** QR code as an SVG data URI: no image libraries or AWT needed on the server. */
    static String qrDataUri(String text) {
        try {
            BitMatrix m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0,
                    Map.of(EncodeHintType.MARGIN, 2));
            StringBuilder path = new StringBuilder();
            for (int y = 0; y < m.getHeight(); y++) {
                for (int x = 0; x < m.getWidth(); x++) {
                    if (m.get(x, y)) path.append('M').append(x).append(' ').append(y).append("h1v1h-1z");
                }
            }
            String svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 " + m.getWidth() + " " + m.getHeight()
                    + "' shape-rendering='crispEdges'><rect width='100%' height='100%' fill='#fff'/>"
                    + "<path d='" + path + "' fill='#000'/></svg>";
            return "data:image/svg+xml;base64," + Base64.getEncoder().encodeToString(svg.getBytes(StandardCharsets.UTF_8));
        } catch (WriterException e) {
            throw new IllegalStateException(e);
        }
    }
}
