package com.trustgate.core.db;

import com.trustgate.core.crypto.Base32;
import com.trustgate.core.crypto.FieldCipher;
import com.trustgate.core.crypto.Masking;
import com.trustgate.core.crypto.PasswordHasher;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import javax.sql.DataSource;

/**
 * Users with encrypted personal data. Every query is a PreparedStatement with bound
 * parameters; no SQL is ever built from user input.
 */
public final class UserDao {
    public record NewUser(String username, char[] password, String displayName, String role,
                          String email, String rrn, String phone) {}

    private static final String COLUMNS = "ID, USERNAME, PASSWORD_HASH, DISPLAY_NAME, USER_ROLE, EMAIL, "
            + "RRN_ENC, PHONE_ENC, OTP_SECRET_ENC, OTP_ENABLED, OTP_LAST_STEP, FAILED_COUNT, LOCKED_UNTIL, CREATED_AT";

    private final DataSource ds;
    private final FieldCipher cipher;
    private final PasswordHasher hasher;

    public UserDao(DataSource ds, FieldCipher cipher, PasswordHasher hasher) {
        this.ds = ds;
        this.cipher = cipher;
        this.hasher = hasher;
    }

    // --- AAD contexts: a ciphertext is only valid in its own row and column -------------------

    static String rrnContext(long id) {
        return "TG_USERS.RRN_ENC:" + id;
    }

    static String phoneContext(long id) {
        return "TG_USERS.PHONE_ENC:" + id;
    }

    static String otpContext(long id) {
        return "TG_USERS.OTP_SECRET_ENC:" + id;
    }

    // --- queries ------------------------------------------------------------------------------

    public Optional<User> findByUsername(String username) {
        return queryOne("SELECT " + COLUMNS + " FROM TG_USERS WHERE USERNAME = ?", username);
    }

    public Optional<User> findById(long id) {
        return queryOne("SELECT " + COLUMNS + " FROM TG_USERS WHERE ID = ?", id);
    }

    /** Exact-match search on the encrypted RRN column through its blind index. */
    public Optional<User> findByRrn(String rrn) {
        String token = cipher.blindIndex("RRN", Masking.normalizeRrn(rrn));
        return queryOne("SELECT " + COLUMNS + " FROM TG_USERS WHERE RRN_IDX = ?", token);
    }

    public Optional<User> findByPhone(String phone) {
        String token = cipher.blindIndex("PHONE", Masking.normalizePhone(phone));
        return queryOne("SELECT " + COLUMNS + " FROM TG_USERS WHERE PHONE_IDX = ?", token);
    }

    public List<User> findAll() {
        List<User> out = new ArrayList<>();
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT " + COLUMNS + " FROM TG_USERS ORDER BY ID");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) out.add(map(rs));
        } catch (SQLException e) {
            throw new DataAccessException(e);
        }
        return out;
    }

    /** Raw RRN_IDX / PHONE_IDX values, for showing what the database actually holds. */
    public Map<Long, String[]> rawIndexes() {
        Map<Long, String[]> out = new TreeMap<>();
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT ID, RRN_IDX, PHONE_IDX FROM TG_USERS");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) out.put(rs.getLong(1), new String[] {rs.getString(2), rs.getString(3)});
        } catch (SQLException e) {
            throw new DataAccessException(e);
        }
        return out;
    }

    // --- decryption ---------------------------------------------------------------------------

    public String rrn(User u) {
        return cipher.decrypt(u.rrnEnc(), rrnContext(u.id()));
    }

    public String phone(User u) {
        return cipher.decrypt(u.phoneEnc(), phoneContext(u.id()));
    }

    public byte[] otpSecret(User u) {
        String b32 = cipher.decrypt(u.otpSecretEnc(), otpContext(u.id()));
        return b32 == null ? null : Base32.decode(b32);
    }

    // --- writes -------------------------------------------------------------------------------

    /**
     * Inserts the row first to obtain its ID, then encrypts the personal data with that ID in
     * the AAD, all in one transaction.
     */
    public long create(NewUser n) {
        try (Connection c = ds.getConnection()) {
            c.setAutoCommit(false);
            try {
                long id;
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO TG_USERS (USERNAME, PASSWORD_HASH, DISPLAY_NAME, USER_ROLE, EMAIL, CREATED_AT) "
                                + "VALUES (?, ?, ?, ?, ?, ?)", new String[] {"ID"})) {
                    ps.setString(1, n.username());
                    ps.setString(2, hasher.hash(n.password()));
                    ps.setString(3, n.displayName());
                    ps.setString(4, n.role());
                    ps.setString(5, n.email());
                    ps.setTimestamp(6, Timestamp.from(Instant.now()));
                    ps.executeUpdate();
                    try (ResultSet keys = ps.getGeneratedKeys()) {
                        keys.next();
                        id = keys.getLong(1);
                    }
                }
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE TG_USERS SET RRN_ENC = ?, RRN_IDX = ?, PHONE_ENC = ?, PHONE_IDX = ? WHERE ID = ?")) {
                    String rrn = Masking.normalizeRrn(n.rrn());
                    String phone = Masking.normalizePhone(n.phone());
                    ps.setString(1, rrn == null ? null : cipher.encrypt(rrn, rrnContext(id)));
                    ps.setString(2, rrn == null ? null : cipher.blindIndex("RRN", rrn));
                    ps.setString(3, phone == null ? null : cipher.encrypt(phone, phoneContext(id)));
                    ps.setString(4, phone == null ? null : cipher.blindIndex("PHONE", phone));
                    ps.setLong(5, id);
                    ps.executeUpdate();
                }
                c.commit();
                return id;
            } catch (SQLException | RuntimeException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new DataAccessException(e);
        }
    }

    public void enableOtp(long id, byte[] secret) {
        update("UPDATE TG_USERS SET OTP_SECRET_ENC = ?, OTP_ENABLED = 1, OTP_LAST_STEP = NULL WHERE ID = ?",
                cipher.encrypt(Base32.encode(secret), otpContext(id)), id);
    }

    public void resetOtp(long id) {
        update("UPDATE TG_USERS SET OTP_SECRET_ENC = NULL, OTP_ENABLED = 0, OTP_LAST_STEP = NULL WHERE ID = ?", id);
    }

    /**
     * Records that an OTP time step was used. The conditional UPDATE is atomic, so two
     * concurrent logins with the same code cannot both succeed. Returns false on replay.
     */
    public boolean consumeOtpStep(long id, long step) {
        return update("UPDATE TG_USERS SET OTP_LAST_STEP = ? WHERE ID = ? "
                + "AND (OTP_LAST_STEP IS NULL OR OTP_LAST_STEP < ?)", step, id, step) == 1;
    }

    /** Counts a failed attempt; locks the account for `lockFor` once `max` is reached. */
    public boolean recordFailure(long id, int max, Duration lockFor) {
        update("UPDATE TG_USERS SET FAILED_COUNT = FAILED_COUNT + 1 WHERE ID = ?", id);
        User u = findById(id).orElseThrow();
        if (u.failedCount() >= max) {
            update("UPDATE TG_USERS SET FAILED_COUNT = 0, LOCKED_UNTIL = ? WHERE ID = ?",
                    Timestamp.from(Instant.now().plus(lockFor)), id);
            return true;
        }
        return false;
    }

    public void resetFailures(long id) {
        update("UPDATE TG_USERS SET FAILED_COUNT = 0, LOCKED_UNTIL = NULL WHERE ID = ?", id);
    }

    /** Re-encrypts every value written under an older data key. Returns the number of values. */
    public int reencryptAll() {
        int changed = 0;
        for (User u : findAll()) {
            String rrn = u.rrnEnc();
            String phone = u.phoneEnc();
            String otp = u.otpSecretEnc();
            boolean dirty = false;
            if (cipher.needsReencryption(rrn)) {
                rrn = cipher.encrypt(cipher.decrypt(rrn, rrnContext(u.id())), rrnContext(u.id()));
                dirty = true;
                changed++;
            }
            if (cipher.needsReencryption(phone)) {
                phone = cipher.encrypt(cipher.decrypt(phone, phoneContext(u.id())), phoneContext(u.id()));
                dirty = true;
                changed++;
            }
            if (cipher.needsReencryption(otp)) {
                otp = cipher.encrypt(cipher.decrypt(otp, otpContext(u.id())), otpContext(u.id()));
                dirty = true;
                changed++;
            }
            if (dirty) {
                update("UPDATE TG_USERS SET RRN_ENC = ?, PHONE_ENC = ?, OTP_SECRET_ENC = ? WHERE ID = ?",
                        rrn, phone, otp, u.id());
            }
        }
        return changed;
    }

    /** How many encrypted values each data-key version currently protects. */
    public Map<Integer, Integer> valuesPerKeyVersion() {
        Map<Integer, Integer> out = new TreeMap<>();
        for (User u : findAll()) {
            for (String v : new String[] {u.rrnEnc(), u.phoneEnc(), u.otpSecretEnc()}) {
                if (v != null) out.merge(FieldCipher.versionOf(v), 1, Integer::sum);
            }
        }
        return out;
    }

    // --- helpers ------------------------------------------------------------------------------

    private Optional<User> queryOne(String sql, Object param) {
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, param);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(map(rs)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new DataAccessException(e);
        }
    }

    private int update(String sql, Object... params) {
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, params);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new DataAccessException(e);
        }
    }

    private static void bind(PreparedStatement ps, Object... params) throws SQLException {
        for (int i = 0; i < params.length; i++) {
            Object p = params[i];
            if (p == null) ps.setNull(i + 1, Types.VARCHAR);
            else if (p instanceof Long l) ps.setLong(i + 1, l);
            else if (p instanceof Integer n) ps.setInt(i + 1, n);
            else if (p instanceof Timestamp t) ps.setTimestamp(i + 1, t);
            else ps.setString(i + 1, p.toString());
        }
    }

    private static User map(ResultSet rs) throws SQLException {
        Timestamp locked = rs.getTimestamp(13);
        long lastStep = rs.getLong(11);
        boolean lastStepNull = rs.wasNull();
        return new User(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
                rs.getString(6), rs.getString(7), rs.getString(8), rs.getString(9), rs.getInt(10) == 1,
                lastStepNull ? null : lastStep, rs.getInt(12), locked == null ? null : locked.toInstant(),
                rs.getTimestamp(14).toInstant());
    }
}
