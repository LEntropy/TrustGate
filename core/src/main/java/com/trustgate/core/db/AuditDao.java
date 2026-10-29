package com.trustgate.core.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/** Security audit trail: logins, OTP results, token issuance, logouts and key operations. */
public final class AuditDao {
    public record Entry(Instant ts, String username, String event, String detail, String ip) {}

    private final DataSource ds;

    public AuditDao(DataSource ds) {
        this.ds = ds;
    }

    public void log(String username, String event, String detail, String ip) {
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO TG_AUDIT (TS, USERNAME, EVENT_TYPE, DETAIL, CLIENT_IP) VALUES (?, ?, ?, ?, ?)")) {
            ps.setTimestamp(1, Timestamp.from(Instant.now()));
            ps.setString(2, clip(username, 50));
            ps.setString(3, event);
            ps.setString(4, clip(detail, 400));
            ps.setString(5, clip(ip, 45));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DataAccessException(e);
        }
    }

    public List<Entry> recent(int limit) {
        List<Entry> out = new ArrayList<>();
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "SELECT TS, USERNAME, EVENT_TYPE, DETAIL, CLIENT_IP FROM TG_AUDIT ORDER BY ID DESC "
                             + "FETCH FIRST ? ROWS ONLY")) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new Entry(rs.getTimestamp(1).toInstant(), rs.getString(2), rs.getString(3),
                            rs.getString(4), rs.getString(5)));
                }
            }
        } catch (SQLException e) {
            throw new DataAccessException(e);
        }
        return out;
    }

    private static String clip(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }
}
