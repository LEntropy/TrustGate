package com.trustgate.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.trustgate.core.crypto.CryptoException;
import com.trustgate.core.crypto.FieldCipher;
import com.trustgate.core.crypto.KeyManager;
import com.trustgate.core.crypto.KeyStoreKekProvider;
import com.trustgate.core.crypto.PasswordHasher;
import com.trustgate.core.db.Schema;
import com.trustgate.core.db.User;
import com.trustgate.core.db.UserDao;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EncryptionTest {
    @TempDir
    Path dir;

    private JdbcDataSource ds;
    private KeyManager keys;
    private FieldCipher cipher;
    private UserDao users;

    @BeforeEach
    void setUp() throws Exception {
        ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:mem:" + System.nanoTime() + ";MODE=Oracle;DB_CLOSE_DELAY=-1");
        Schema.ensure(ds);
        keys = new KeyManager(ds, KeyStoreKekProvider.openOrCreate(dir.resolve("kek.p12"), "pw".toCharArray()));
        keys.initialize();
        cipher = new FieldCipher(keys);
        users = new UserDao(ds, cipher, new PasswordHasher(new SecureRandom()));
    }

    private long createHong() {
        return users.create(new UserDao.NewUser("hong", "Pw!12345".toCharArray(), "홍길동", User.ROLE_USER,
                "hong@example.com", "900101-1234567", "010-1234-5678"));
    }

    @Test
    @DisplayName("Round trip, and equal plaintexts give different ciphertexts (random nonce)")
    void roundTrip() {
        String a = cipher.encrypt("900101-1234567", "T.C:1");
        String b = cipher.encrypt("900101-1234567", "T.C:1");
        assertNotEquals(a, b);
        assertTrue(a.startsWith("v1:"));
        assertEquals("900101-1234567", cipher.decrypt(a, "T.C:1"));
    }

    @Test
    @DisplayName("A single flipped bit in the ciphertext is detected (GCM tag)")
    void tamperDetected() {
        String stored = cipher.encrypt("secret", "T.C:1");
        byte[] raw = Base64.getDecoder().decode(stored.substring(3));
        raw[raw.length / 2] ^= 1;
        String tampered = "v1:" + Base64.getEncoder().encodeToString(raw);
        assertThrows(CryptoException.class, () -> cipher.decrypt(tampered, "T.C:1"));
    }

    @Test
    @DisplayName("Ciphertext copied to another row does not decrypt (AAD binds row and column)")
    void contextBinding() {
        String forRow1 = cipher.encrypt("900101-1234567", "TG_USERS.RRN_ENC:1");
        assertThrows(CryptoException.class, () -> cipher.decrypt(forRow1, "TG_USERS.RRN_ENC:2"));
        assertThrows(CryptoException.class, () -> cipher.decrypt(forRow1, "TG_USERS.PHONE_ENC:1"));
    }

    @Test
    @DisplayName("After key rotation old values still decrypt and new ones use the new version")
    void rotation() {
        String old = cipher.encrypt("before", "T.C:1");
        assertEquals(2, keys.rotate());
        String fresh = cipher.encrypt("after", "T.C:1");
        assertTrue(fresh.startsWith("v2:"));
        assertEquals("before", cipher.decrypt(old, "T.C:1"));
        assertTrue(cipher.needsReencryption(old));
        assertFalse(cipher.needsReencryption(fresh));
    }

    @Test
    @DisplayName("Data keys cannot be unwrapped with a different KEK")
    void wrongKek() throws Exception {
        String stored = cipher.encrypt("x", "T.C:1");
        KeyManager other = new KeyManager(ds,
                KeyStoreKekProvider.openOrCreate(dir.resolve("other.p12"), "pw".toCharArray()));
        other.initialize();
        assertThrows(CryptoException.class, () -> new FieldCipher(other).decrypt(stored, "T.C:1"));
    }

    @Test
    @DisplayName("Database holds no plaintext personal data, but blind-index search still finds the row")
    void storedEncryptedAndSearchable() {
        long id = createHong();
        User u = users.findById(id).orElseThrow();
        assertFalse(u.rrnEnc().contains("900101"));
        assertFalse(u.phoneEnc().contains("1234"));
        assertEquals("9001011234567", users.rrn(u));
        assertEquals("01012345678", users.phone(u));
        assertEquals(id, users.findByRrn("900101-1234567").orElseThrow().id());
        assertEquals(id, users.findByPhone("01012345678").orElseThrow().id());
        assertTrue(users.findByRrn("900101-1234568").isEmpty());
        String idx = users.rawIndexes().get(id)[0];
        assertEquals(64, idx.length());
        assertFalse(idx.contains("900101"));
    }

    @Test
    @DisplayName("Blind index differs per field even for the same value")
    void blindIndexSeparation() {
        assertEquals(cipher.blindIndex("RRN", "123"), cipher.blindIndex("RRN", "123"));
        assertNotEquals(cipher.blindIndex("RRN", "123"), cipher.blindIndex("PHONE", "123"));
    }

    @Test
    @DisplayName("Re-encryption moves every value to the active key version")
    void reencrypt() {
        long id = createHong();
        users.enableOtp(id, new byte[20]);
        assertEquals(Map.of(1, 3), users.valuesPerKeyVersion());
        keys.rotate();
        assertEquals(3, users.reencryptAll());
        assertEquals(Map.of(2, 3), users.valuesPerKeyVersion());
        User u = users.findById(id).orElseThrow();
        assertEquals("9001011234567", users.rrn(u));
        assertEquals(0, users.reencryptAll());
    }

    @Test
    @DisplayName("An OTP time step can be used only once (replay protection)")
    void otpReplay() {
        long id = createHong();
        assertTrue(users.consumeOtpStep(id, 1000));
        assertFalse(users.consumeOtpStep(id, 1000));
        assertFalse(users.consumeOtpStep(id, 999));
        assertTrue(users.consumeOtpStep(id, 1001));
    }

    @Test
    @DisplayName("Account locks after 5 failures")
    void lockout() {
        long id = createHong();
        for (int i = 0; i < 4; i++) assertFalse(users.recordFailure(id, 5, Duration.ofMinutes(5)));
        assertTrue(users.recordFailure(id, 5, Duration.ofMinutes(5)));
        assertTrue(users.findById(id).orElseThrow().isLocked(java.time.Instant.now()));
        users.resetFailures(id);
        assertFalse(users.findById(id).orElseThrow().isLocked(java.time.Instant.now()));
    }
}
