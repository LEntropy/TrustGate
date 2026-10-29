package com.trustgate.idp;

import com.trustgate.core.crypto.FieldCipher;
import com.trustgate.core.crypto.KekProvider;
import com.trustgate.core.crypto.KeyManager;
import com.trustgate.core.crypto.KeyStoreKekProvider;
import com.trustgate.core.crypto.PasswordHasher;
import com.trustgate.core.crypto.Totp;
import com.trustgate.core.db.AuditDao;
import com.trustgate.core.db.Schema;
import com.trustgate.core.db.User;
import com.trustgate.core.db.UserDao;
import com.trustgate.core.token.SigningKeys;
import com.trustgate.core.web.Web;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Wires the IdP together at startup. Configuration comes from environment variables so the
 * same WAR runs against H2 (quick start) or Oracle (docker compose).
 */
@WebListener
public class Idp implements ServletContextListener {
    private static final Logger LOG = Logger.getLogger(Idp.class.getName());
    private static final String ATTR = Idp.class.getName();

    /** A registered service provider (OIDC confidential client). */
    public record Client(String id, String name, String secret, String baseUrl) {
        public String redirectUri() {
            return baseUrl + "/callback";
        }

        public String backchannelLogoutUri() {
            return baseUrl + "/backchannel-logout";
        }

        public String postLogoutRedirectUri() {
            return baseUrl + "/logged-out";
        }
    }

    public static final int MAX_FAILURES = 5;
    public static final Duration LOCK_DURATION = Duration.ofMinutes(5);

    public HikariDataSource ds;
    public KeyManager keys;
    public FieldCipher cipher;
    public UserDao users;
    public AuditDao audit;
    public SigningKeys signing;
    public PasswordHasher hasher;
    public final Totp totp = new Totp(Clock.systemUTC());
    public final AuthCodeStore codes = new AuthCodeStore();
    public final SsoRegistry sso = new SsoRegistry();
    public final Map<String, Client> clients = new LinkedHashMap<>();
    public final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    public String issuer;
    public boolean demoMode;

    public static Idp get(ServletContext ctx) {
        return (Idp) ctx.getAttribute(ATTR);
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        issuer = Web.env("TG_ISSUER", "http://localhost:8080/idp");
        demoMode = Boolean.parseBoolean(Web.env("TG_DEMO_MODE", "false"));
        Path dataDir = Path.of(Web.env("TG_DATA_DIR", "/data"));

        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(Web.env("TG_DB_URL", "jdbc:h2:file:" + dataDir.resolve("trustgate") + ";MODE=Oracle"));
        // Drivers in WEB-INF/lib are not visible to DriverManager's auto-registration under Tomcat.
        cfg.setDriverClassName(cfg.getJdbcUrl().startsWith("jdbc:oracle:") ? "oracle.jdbc.OracleDriver" : "org.h2.Driver");
        cfg.setUsername(Web.env("TG_DB_USER", "sa"));
        cfg.setPassword(Web.env("TG_DB_PASSWORD", ""));
        cfg.setMaximumPoolSize(8);
        cfg.setPoolName("trustgate");
        ds = new HikariDataSource(cfg);

        try {
            boolean created = Schema.ensure(ds);
            KekProvider kek = KeyStoreKekProvider.openOrCreate(dataDir.resolve("kek.p12"),
                    Web.env("TG_KEK_PASSWORD", "change-me").toCharArray());
            keys = new KeyManager(ds, kek);
            keys.initialize();
            cipher = new FieldCipher(keys);
            hasher = new PasswordHasher(new SecureRandom());
            users = new UserDao(ds, cipher, hasher);
            audit = new AuditDao(ds);
            signing = SigningKeys.loadOrCreate(dataDir.resolve("idp-signing.properties"), kek);
            if (created) seed();
            audit.log(null, "IDP_STARTED", "db=" + cfg.getJdbcUrl().split(":")[1] + " kek=" + kek.describe(), null);
        } catch (Exception e) {
            ds.close();
            throw new IllegalStateException("IdP startup failed: " + e.getMessage(), e);
        }

        String spBase = Web.env("TG_SP_BASE", "http://localhost:8080");
        addClient("portal", "사내 포털", spBase);
        addClient("mail", "웹메일", spBase);
        event.getServletContext().setAttribute(ATTR, this);
        LOG.info("TrustGate IdP ready: issuer=" + issuer + " demoMode=" + demoMode);
    }

    private void addClient(String id, String name, String spBase) {
        String secret = Web.env("TG_CLIENT_" + id.toUpperCase() + "_SECRET", id + "-secret-change-me");
        clients.put(id, new Client(id, name, secret, spBase + "/" + id));
    }

    /** Demo accounts. The resident registration numbers are made up. */
    private void seed() {
        users.create(new UserDao.NewUser("admin", "Admin!2345".toCharArray(), "보안관리자", User.ROLE_ADMIN,
                "admin@trustgate.local", "800101-1000001", "010-1000-0001"));
        users.create(new UserDao.NewUser("user1", "User!2345".toCharArray(), "홍길동", User.ROLE_USER,
                "hong@trustgate.local", "900101-1234567", "010-1234-5678"));
        users.create(new UserDao.NewUser("user2", "User!2345".toCharArray(), "김영희", User.ROLE_USER,
                "kim@trustgate.local", "950505-2345678", "010-9876-5432"));
        LOG.info("seeded demo users admin, user1, user2");
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (ds != null) ds.close();
    }
}
