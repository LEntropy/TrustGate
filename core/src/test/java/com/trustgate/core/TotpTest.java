package com.trustgate.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.trustgate.core.crypto.Base32;
import com.trustgate.core.crypto.Totp;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TotpTest {
    private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @ParameterizedTest(name = "T={0} -> {1}")
    @DisplayName("RFC 6238 Appendix B test vectors (HMAC-SHA1, 8 digits)")
    @CsvSource({
            "59, 94287082",
            "1111111109, 07081804",
            "1111111111, 14050471",
            "1234567890, 89005924",
            "2000000000, 69279037",
            "20000000000, 65353130"})
    void rfc6238Vectors(long time, String expected) {
        assertEquals(expected, Totp.code(RFC_SECRET, time / 30, 8, "HmacSHA1"));
    }

    @ParameterizedTest(name = "\"{0}\" -> {1}")
    @DisplayName("RFC 4648 Base32 test vectors")
    @CsvSource({"f, MY", "fo, MZXQ", "foo, MZXW6", "foob, MZXW6YQ", "fooba, MZXW6YTB", "foobar, MZXW6YTBOI"})
    void base32Vectors(String in, String out) {
        assertEquals(out, Base32.encode(in.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(in, new String(Base32.decode(out.toLowerCase()), StandardCharsets.US_ASCII));
    }

    private static Totp at(long epochSeconds) {
        return new Totp(Clock.fixed(Instant.ofEpochSecond(epochSeconds), ZoneOffset.UTC));
    }

    @Test
    @DisplayName("Codes from the previous and next 30 s step are accepted (clock drift), older ones are not")
    void windowOfOneStep() {
        long t = 1_700_000_010L;
        long step = t / 30;
        Totp totp = at(t);
        assertEquals(step - 1, totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 1, 6, "HmacSHA1")).getAsLong());
        assertEquals(step + 1, totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step + 1, 6, "HmacSHA1")).getAsLong());
        assertTrue(totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 2, 6, "HmacSHA1")).isEmpty());
    }

    @Test
    @DisplayName("Malformed input is rejected without computing anything")
    void rejectsMalformed() {
        Totp totp = at(1_700_000_000L);
        assertTrue(totp.verify(RFC_SECRET, null).isEmpty());
        assertTrue(totp.verify(RFC_SECRET, "12345").isEmpty());
        assertTrue(totp.verify(RFC_SECRET, "12a456").isEmpty());
        assertTrue(totp.verify(RFC_SECRET, "1234567").isEmpty());
    }

    @Test
    @DisplayName("Provisioning URI follows the Key Uri Format used by authenticator apps")
    void provisioningUri() {
        String uri = Totp.provisioningUri("TrustGate", "user1", RFC_SECRET);
        assertEquals("otpauth://totp/TrustGate:user1?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                + "&issuer=TrustGate&algorithm=SHA1&digits=6&period=30", uri);
    }
}
