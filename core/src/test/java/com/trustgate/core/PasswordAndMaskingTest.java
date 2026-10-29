package com.trustgate.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.trustgate.core.crypto.Masking;
import com.trustgate.core.crypto.PasswordHasher;
import java.security.SecureRandom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordAndMaskingTest {
    private final PasswordHasher hasher = new PasswordHasher(new SecureRandom());

    @Test
    @DisplayName("PBKDF2 hash verifies only the right password, with 310,000 iterations")
    void hashAndVerify() {
        String h = hasher.hash("S3cret!pw".toCharArray());
        assertTrue(h.startsWith("pbkdf2_sha256$310000$"));
        assertTrue(hasher.verify("S3cret!pw".toCharArray(), h));
        assertFalse(hasher.verify("S3cret!pW".toCharArray(), h));
    }

    @Test
    @DisplayName("Same password gets a different salt and hash every time")
    void saltedHashes() {
        assertNotEquals(hasher.hash("same".toCharArray()), hasher.hash("same".toCharArray()));
    }

    @Test
    @DisplayName("Malformed stored hashes never verify")
    void malformed() {
        assertFalse(hasher.verify("x".toCharArray(), null));
        assertFalse(hasher.verify("x".toCharArray(), "plaintext"));
        assertFalse(hasher.verify("x".toCharArray(), "md5$1$a$b"));
        assertFalse(hasher.verify("x".toCharArray(), "pbkdf2_sha256$NaN$AAAA$AAAA"));
    }

    @Test
    @DisplayName("Masking keeps only what a screen needs to show")
    void masking() {
        assertEquals("900101-1******", Masking.rrn("900101-1234567"));
        assertEquals("900101-1******", Masking.rrn("9001011234567"));
        assertEquals("******-*******", Masking.rrn("123"));
        assertEquals("010-****-5678", Masking.phone("010-1234-5678"));
        assertEquals("h***@example.com", Masking.email("hong@example.com"));
        assertTrue(Masking.isValidRrn("900101-1234567"));
        assertFalse(Masking.isValidRrn("900101-123456"));
    }
}
