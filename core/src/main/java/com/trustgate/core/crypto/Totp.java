package com.trustgate.core.crypto;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Time-based one-time passwords (RFC 6238 on top of HOTP, RFC 4226), compatible with
 * Google Authenticator and Microsoft Authenticator.
 */
public final class Totp {
    public static final int PERIOD_SECONDS = 30;
    public static final int DIGITS = 6;
    /** Accept codes from one step before and after the current one to absorb clock drift. */
    public static final int WINDOW = 1;

    private static final int[] POW10 = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    private final Clock clock;

    public Totp(Clock clock) {
        this.clock = clock;
    }

    public static byte[] newSecret(SecureRandom random) {
        byte[] secret = new byte[20];  // 160 bits, the HMAC-SHA1 block recommendation of RFC 4226
        random.nextBytes(secret);
        return secret;
    }

    public long currentStep() {
        return Math.floorDiv(clock.millis() / 1000, PERIOD_SECONDS);
    }

    /** HOTP value for a time step; `algorithm` is a JCA HMAC name such as "HmacSHA1". */
    public static String code(byte[] secret, long step, int digits, String algorithm) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(secret, algorithm));
            byte[] counter = new byte[8];
            for (int i = 7; i >= 0; i--) {
                counter[i] = (byte) (step & 0xFF);
                step >>>= 8;
            }
            byte[] h = mac.doFinal(counter);
            // Dynamic truncation (RFC 4226 section 5.3)
            int offset = h[h.length - 1] & 0x0F;
            int binary = ((h[offset] & 0x7F) << 24) | ((h[offset + 1] & 0xFF) << 16)
                    | ((h[offset + 2] & 0xFF) << 8) | (h[offset + 3] & 0xFF);
            String s = Integer.toString(binary % POW10[digits]);
            return "0".repeat(digits - s.length()) + s;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public String currentCode(byte[] secret) {
        return code(secret, currentStep(), DIGITS, "HmacSHA1");
    }

    /**
     * Checks `input` against the steps around now. Returns the matching step, or empty.
     * The caller must store the step and reject any later code with a step that is not
     * greater, otherwise a code observed by an attacker could be replayed within its window.
     */
    public OptionalLong verify(byte[] secret, String input) {
        if (input == null) return OptionalLong.empty();
        String code = input.trim();
        if (code.length() != DIGITS || !code.chars().allMatch(Character::isDigit)) {
            return OptionalLong.empty();
        }
        long now = currentStep();
        OptionalLong match = OptionalLong.empty();
        // Compare against every candidate so the timing does not reveal which step matched.
        for (long step = now - WINDOW; step <= now + WINDOW; step++) {
            byte[] expected = code(secret, step, DIGITS, "HmacSHA1").getBytes(StandardCharsets.US_ASCII);
            if (MessageDigest.isEqual(expected, code.getBytes(StandardCharsets.US_ASCII)) && match.isEmpty()) {
                match = OptionalLong.of(step);
            }
        }
        return match;
    }

    /** otpauth:// URI encoded in the enrollment QR code. */
    public static String provisioningUri(String issuer, String account, byte[] secret) {
        String label = enc(issuer) + ":" + enc(account);
        return "otpauth://totp/" + label + "?secret=" + Base32.encode(secret) + "&issuer=" + enc(issuer)
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + PERIOD_SECONDS;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
