package com.trustgate.core.db;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.trustgate.core.crypto.FieldCipher;
import com.trustgate.core.crypto.KeyManager;
import com.trustgate.core.crypto.KeyStoreKekProvider;
import com.trustgate.core.crypto.PasswordHasher;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReencryptRaceTest {
    @TempDir
    Path dir;

    @Test
    @DisplayName("Re-encryption does not overwrite a value that changed after it was read")
    void keepsNewerValue() throws Exception {
        JdbcDataSource ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:mem:" + System.nanoTime() + ";MODE=Oracle;DB_CLOSE_DELAY=-1");
        Schema.ensure(ds);
        KeyManager keys = new KeyManager(ds, KeyStoreKekProvider.openOrCreate(dir.resolve("kek.p12"), "pw".toCharArray()));
        keys.initialize();
        UserDao users = new UserDao(ds, new FieldCipher(keys), new PasswordHasher(new SecureRandom()));
        long id = users.create(new UserDao.NewUser("hong", "Pw!12345".toCharArray(), "홍길동", User.ROLE_USER,
                "hong@example.com", "900101-1234567", "010-1234-5678"));

        byte[] oldSecret = new byte[20];
        users.enableOtp(id, oldSecret);
        keys.rotate();

        // Re-encryption reads the row (old OTP secret, key v1) ...
        String readByReencrypt = users.findById(id).orElseThrow().otpSecretEnc();
        // ... meanwhile the user resets and re-enrols OTP with a new secret (written with key v2) ...
        byte[] newSecret = new byte[20];
        Arrays.fill(newSecret, (byte) 7);
        users.enableOtp(id, newSecret);
        // ... then re-encryption writes back what it read. It must not replace the new secret.
        assertEquals(0, users.reencryptColumn("OTP_SECRET_ENC", readByReencrypt, UserDao.otpContext(id), id));
        assertArrayEquals(newSecret, users.otpSecret(users.findById(id).orElseThrow()));
    }
}
