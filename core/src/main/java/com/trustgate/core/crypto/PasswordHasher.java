package com.trustgate.core.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-HMAC-SHA256 password hashing with a per-user salt.
 * Stored format: {@code pbkdf2_sha256$<iterations>$<salt b64>$<hash b64>} so the work
 * factor can be raised later without breaking existing hashes.
 */
public final class PasswordHasher {
    public static final int ITERATIONS = 310_000;  // OWASP 2023 recommendation for PBKDF2-SHA256
    private static final String PREFIX = "pbkdf2_sha256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private final SecureRandom random;
    private final int iterations;

    public PasswordHasher(SecureRandom random) {
        this(random, ITERATIONS);
    }

    PasswordHasher(SecureRandom random, int iterations) {
        this.random = random;
        this.iterations = iterations;
    }

    public String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = derive(password, salt, iterations);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return PREFIX + "$" + iterations + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(hash);
    }

    public boolean verify(char[] password, String stored) {
        String[] parts = stored == null ? new String[0] : stored.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) return false;
        int iter;
        try {
            iter = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] expected = Base64.getDecoder().decode(parts[3]);
        // Constant-time comparison: no early exit that leaks how many bytes matched.
        return MessageDigest.isEqual(expected, derive(password, salt, iter));
    }

    /** Used to burn the same CPU time for unknown usernames, so timing does not reveal them. */
    public void dummyVerify(char[] password) {
        derive(password, new byte[SALT_BYTES], iterations);
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } finally {
            spec.clearPassword();
        }
    }
}
