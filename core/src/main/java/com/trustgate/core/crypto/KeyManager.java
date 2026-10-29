package com.trustgate.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;

/**
 * Envelope encryption key hierarchy.
 *
 * <pre>
 *   KEK (KekProvider: key store / HSM / KMS)
 *    └─ wraps ─► data keys (DEK), stored wrapped in TG_KEYS with a version number
 *                 └─ encrypt ─► column values, each tagged with the DEK version
 * </pre>
 *
 * Rotation creates a new active DEK; older versions stay available for decryption until
 * every row has been re-encrypted. The blind-index key (purpose IDX) is separate from the
 * encryption keys so that search tokens reveal nothing about the ciphertexts.
 */
public final class KeyManager {
    public static final String PURPOSE_ENC = "ENC";
    public static final String PURPOSE_IDX = "IDX";

    public record KeyInfo(int version, String purpose, String status, Instant createdAt) {}

    private final DataSource ds;
    private final KekProvider kek;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, SecretKey> cache = new ConcurrentHashMap<>();
    private volatile int activeVersion;

    public KeyManager(DataSource ds, KekProvider kek) {
        this.ds = ds;
        this.kek = kek;
    }

    /** Creates the first keys on an empty database and loads the active version. */
    public synchronized void initialize() {
        try (Connection c = ds.getConnection()) {
            if (maxVersion(c, PURPOSE_ENC) == 0) insertKey(c, 1, PURPOSE_ENC);
            if (maxVersion(c, PURPOSE_IDX) == 0) insertKey(c, 1, PURPOSE_IDX);
            activeVersion = loadActiveVersion(c);
        } catch (SQLException e) {
            throw new IllegalStateException("cannot initialise keys", e);
        }
    }

    public int activeVersion() {
        return activeVersion;
    }

    public String kekDescription() {
        return kek.describe();
    }

    public SecretKey dataKey(int version) {
        return key(version, PURPOSE_ENC);
    }

    public SecretKey indexKey() {
        return key(1, PURPOSE_IDX);
    }

    /** Generates a new active data key and retires the previous one. Returns the new version. */
    public synchronized int rotate() {
        try (Connection c = ds.getConnection()) {
            c.setAutoCommit(false);
            try {
                int next = maxVersion(c, PURPOSE_ENC) + 1;
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE TG_KEYS SET STATUS = 'RETIRED' WHERE PURPOSE = ? AND STATUS = 'ACTIVE'")) {
                    ps.setString(1, PURPOSE_ENC);
                    ps.executeUpdate();
                }
                insertKey(c, next, PURPOSE_ENC);
                c.commit();
                activeVersion = next;
                return next;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("key rotation failed", e);
        }
    }

    /**
     * Destroys a retired data key: the wrapped key material is deleted and the version is marked
     * DESTROYED, so old backups encrypted under it can no longer be decrypted. The caller must
     * first make sure no stored value still uses this version (re-encrypt, then check the count).
     * Only RETIRED encryption keys qualify; the active key and the index key never do.
     */
    public synchronized void destroy(int version) {
        if (version == activeVersion) throw new CryptoException("the active data key cannot be destroyed");
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement("UPDATE TG_KEYS SET STATUS = 'DESTROYED', WRAPPED_KEY = 'DESTROYED' "
                     + "WHERE VERSION = ? AND PURPOSE = ? AND STATUS = 'RETIRED'")) {
            ps.setInt(1, version);
            ps.setString(2, PURPOSE_ENC);
            if (ps.executeUpdate() != 1) throw new CryptoException("only a retired data key can be destroyed: v" + version);
        } catch (SQLException e) {
            throw new IllegalStateException("key destruction failed", e);
        }
        cache.remove(PURPOSE_ENC + version);
    }

    public List<KeyInfo> list() {
        List<KeyInfo> out = new ArrayList<>();
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "SELECT VERSION, PURPOSE, STATUS, CREATED_AT FROM TG_KEYS ORDER BY PURPOSE, VERSION DESC");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                out.add(new KeyInfo(rs.getInt(1), rs.getString(2), rs.getString(3),
                        rs.getTimestamp(4).toInstant()));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    private SecretKey key(int version, String purpose) {
        return cache.computeIfAbsent(purpose + version, k -> {
            try (Connection c = ds.getConnection();
                 PreparedStatement ps = c.prepareStatement(
                         "SELECT WRAPPED_KEY, STATUS FROM TG_KEYS WHERE VERSION = ? AND PURPOSE = ?")) {
                ps.setInt(1, version);
                ps.setString(2, purpose);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new CryptoException("unknown key version " + purpose + version);
                    if ("DESTROYED".equals(rs.getString(2))) throw new CryptoException("key " + purpose + version + " was destroyed");
                    byte[] raw = kek.unwrap(Base64.getDecoder().decode(rs.getString(1)), aad(version, purpose));
                    return new SecretKeySpec(raw, "AES");
                }
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        });
    }

    private void insertKey(Connection c, int version, String purpose) throws SQLException {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String wrapped = Base64.getEncoder().encodeToString(kek.wrap(raw, aad(version, purpose)));
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO TG_KEYS (VERSION, PURPOSE, WRAPPED_KEY, STATUS, CREATED_AT) VALUES (?, ?, ?, 'ACTIVE', ?)")) {
            ps.setInt(1, version);
            ps.setString(2, purpose);
            ps.setString(3, wrapped);
            ps.setTimestamp(4, Timestamp.from(Instant.now()));
            ps.executeUpdate();
        }
    }

    private static int maxVersion(Connection c, String purpose) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT MAX(VERSION) FROM TG_KEYS WHERE PURPOSE = ?")) {
            ps.setString(1, purpose);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }

    private static int loadActiveVersion(Connection c) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT MAX(VERSION) FROM TG_KEYS WHERE PURPOSE = ? AND STATUS = 'ACTIVE'")) {
            ps.setString(1, PURPOSE_ENC);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    /** Binds a wrapped key to its version and purpose so wrapped keys cannot be swapped. */
    private static byte[] aad(int version, String purpose) {
        return ("TG_KEYS:" + purpose + ":" + version).getBytes(StandardCharsets.UTF_8);
    }
}
