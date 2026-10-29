package com.trustgate.idp;

import com.trustgate.core.crypto.CryptoException;
import com.trustgate.core.crypto.FieldCipher;
import com.trustgate.core.crypto.KeyManager;
import com.trustgate.core.crypto.Masking;
import com.trustgate.core.db.User;
import com.trustgate.core.db.UserDao;
import com.trustgate.core.web.Web;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Security console: users with their encrypted columns as stored, key versions, rotation and
 * re-encryption, blind-index search and the audit trail. Administrators only.
 */
@WebServlet("/admin")
public class AdminServlet extends HttpServlet {
    private static final Pattern USERNAME = Pattern.compile("[a-z][a-z0-9_]{2,29}");

    /** One table row: what the database holds next to what an administrator may see. */
    public record Row(long id, String username, String name, String role, String rrnMasked, String phoneMasked,
                      String rrnEnc, String rrnIdx, String phoneEnc, int rrnKeyVersion, boolean otp,
                      boolean locked) {}

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        if (requireAdmin(idp, req, resp).isEmpty()) return;
        show(idp, req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Idp idp = Idp.get(getServletContext());
        Optional<SsoSession> admin = requireAdmin(idp, req, resp);
        if (admin.isEmpty()) return;
        if (!Web.validCsrf(req)) {
            Flow.error(req, resp, 400, "요청이 만료되었거나 위조되었습니다. (CSRF 토큰 불일치)");
            return;
        }
        String who = admin.get().username();
        String ip = Web.clientIp(req);
        String action = String.valueOf(req.getParameter("action"));
        String message;
        switch (action) {
            case "rotate" -> {
                int v = idp.keys.rotate();
                idp.audit.log(who, "KEY_ROTATED", "new active data key v" + v, ip);
                message = "새 데이터 키 v" + v + "를 생성해 활성화했습니다. 기존 값은 이전 키로 계속 복호화됩니다.";
            }
            case "destroyKey" -> {
                int v = Integer.parseInt(req.getParameter("version"));
                int remaining = idp.users.valuesPerKeyVersion().getOrDefault(v, 0);
                if (remaining > 0) {
                    message = "키 v" + v + "로 암호화된 값이 아직 " + remaining + "개 있어 폐기할 수 없습니다. 먼저 재암호화해 주세요.";
                } else {
                    try {
                        idp.keys.destroy(v);
                        idp.audit.log(who, "KEY_DESTROYED", "retired data key v" + v + " destroyed", ip);
                        message = "사용이 끝난 데이터 키 v" + v + "를 폐기했습니다. 이 키로 암호화된 예전 백업은 더 이상 복호화할 수 없습니다.";
                    } catch (CryptoException e) {
                        message = "키 v" + v + "는 폐기할 수 없습니다. 사용이 끝난(RETIRED) 데이터 키만 폐기할 수 있습니다.";
                    }
                }
            }
            case "reencrypt" -> {
                int n = idp.users.reencryptAll();
                idp.audit.log(who, "DATA_REENCRYPTED", n + " values moved to v" + idp.keys.activeVersion(), ip);
                message = "암호화된 값 " + n + "개를 활성 키 v" + idp.keys.activeVersion() + "로 다시 암호화했습니다.";
            }
            case "search" -> {
                String rrn = req.getParameter("rrn");
                if (!Masking.isValidRrn(rrn)) {
                    req.setAttribute("searchError", "주민등록번호 13자리를 입력해 주세요.");
                } else {
                    Optional<User> found = idp.users.findByRrn(rrn);
                    // The audit log gets the masked value only, never the number that was searched.
                    idp.audit.log(who, "PII_SEARCH", "rrn=" + Masking.rrn(rrn) + " found=" + found.isPresent(), ip);
                    req.setAttribute("searchToken", idp.cipher.blindIndex("RRN", Masking.normalizeRrn(rrn)));
                    req.setAttribute("searchResult", found.map(u -> u.username() + " (" + u.displayName() + ")")
                            .orElse("일치하는 사용자가 없습니다."));
                }
                show(idp, req, resp);
                return;
            }
            case "create" -> message = createUser(idp, req, who, ip);
            case "resetOtp", "unlock" -> {
                long id = Long.parseLong(req.getParameter("id"));
                User u = idp.users.findById(id).orElseThrow();
                if (action.equals("resetOtp")) {
                    idp.users.resetOtp(id);
                    idp.audit.log(who, "OTP_RESET", "user=" + u.username(), ip);
                    message = u.username() + "의 OTP 등록을 초기화했습니다. 다음 로그인 때 다시 등록합니다.";
                } else {
                    idp.users.resetFailures(id);
                    idp.audit.log(who, "ACCOUNT_UNLOCKED", "user=" + u.username(), ip);
                    message = u.username() + " 계정 잠금을 해제했습니다.";
                }
            }
            default -> message = "알 수 없는 작업입니다.";
        }
        req.getSession().setAttribute(Flow.FLASH, message);
        resp.sendRedirect(req.getContextPath() + "/admin");
    }

    private static String createUser(Idp idp, HttpServletRequest req, String who, String ip) {
        String username = String.valueOf(req.getParameter("username")).trim();
        String name = String.valueOf(req.getParameter("name")).trim();
        String password = String.valueOf(req.getParameter("password"));
        String rrn = req.getParameter("rrn");
        String phone = req.getParameter("phone");
        if (!USERNAME.matcher(username).matches()) return "아이디는 영문 소문자로 시작하는 3~30자(소문자, 숫자, _)여야 합니다.";
        if (name.isEmpty() || name.length() > 50) return "이름을 입력해 주세요.";
        if (password.length() < 8) return "비밀번호는 8자 이상이어야 합니다.";
        if (!Masking.isValidRrn(rrn)) return "주민등록번호 13자리를 입력해 주세요.";
        if (idp.users.findByUsername(username).isPresent()) return "이미 있는 아이디입니다.";
        if (idp.users.findByRrn(rrn).isPresent()) return "같은 주민등록번호로 가입된 사용자가 있습니다. (블라인드 인덱스로 중복 확인)";
        idp.users.create(new UserDao.NewUser(username, password.toCharArray(), name, User.ROLE_USER,
                username + "@trustgate.local", rrn, phone));
        idp.audit.log(who, "USER_CREATED", "user=" + username, ip);
        return username + " 사용자를 만들었습니다. 주민등록번호와 전화번호는 암호화되어 저장됐습니다.";
    }

    private void show(Idp idp, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Map<Long, String[]> idx = idp.users.rawIndexes();
        List<Row> rows = new ArrayList<>();
        Instant now = Instant.now();
        for (User u : idp.users.findAll()) {
            rows.add(new Row(u.id(), u.username(), u.displayName(), u.role(), Masking.rrn(idp.users.rrn(u)),
                    Masking.phone(idp.users.phone(u)), u.rrnEnc(), idx.get(u.id())[0], u.phoneEnc(),
                    u.rrnEnc() == null ? 0 : FieldCipher.versionOf(u.rrnEnc()), u.otpEnabled(), u.isLocked(now)));
        }
        req.setAttribute("rows", rows);
        List<KeyManager.KeyInfo> keys = idp.keys.list();
        Map<Integer, Integer> perVersion = idp.users.valuesPerKeyVersion();
        // A retired data key that no stored value uses any more can be destroyed.
        Set<Integer> destroyable = new HashSet<>();
        for (KeyManager.KeyInfo k : keys) {
            if (KeyManager.PURPOSE_ENC.equals(k.purpose()) && "RETIRED".equals(k.status())
                    && perVersion.getOrDefault(k.version(), 0) == 0) {
                destroyable.add(k.version());
            }
        }
        req.setAttribute("keys", keys);
        req.setAttribute("destroyable", destroyable);
        req.setAttribute("activeVersion", idp.keys.activeVersion());
        req.setAttribute("perVersion", perVersion);
        req.setAttribute("kek", idp.keys.kekDescription());
        req.setAttribute("audit", idp.audit.recent(40));
        req.setAttribute("dbProduct", dbProduct(idp));
        Flow.render(req, resp, "admin");
    }

    private static String dbProduct(Idp idp) {
        try (var c = idp.ds.getConnection()) {
            var md = c.getMetaData();
            return md.getDatabaseProductName() + " " + md.getDatabaseProductVersion().split("\n")[0];
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static Optional<SsoSession> requireAdmin(Idp idp, HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        Optional<SsoSession> sso = Flow.sso(req);
        if (sso.isEmpty()) {
            req.getSession().setAttribute(Flow.RETURN_TO, "/admin");
            resp.sendRedirect(req.getContextPath() + "/login");
            return Optional.empty();
        }
        // Check the role in the database, not only the session, so a demoted admin loses access at once.
        boolean admin = idp.users.findById(sso.get().userId()).map(User::isAdmin).orElse(false);
        if (!admin) {
            idp.audit.log(sso.get().username(), "ACCESS_DENIED", "/admin", Web.clientIp(req));
            Flow.error(req, resp, 403, "관리자만 접근할 수 있는 페이지입니다.");
            return Optional.empty();
        }
        return sso;
    }
}
