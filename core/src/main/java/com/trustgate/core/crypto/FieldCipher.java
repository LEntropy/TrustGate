package com.trustgate.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Mac;

/**
 * Column-level encryption for personal data.
 *
 * <p>Stored value: {@code v<keyVersion>:<base64(nonce || ciphertext || tag)>}. The context
 * (for example {@code TG_USERS.RRN:42}) is the AES-GCM AAD, so a ciphertext only decrypts
 * in the row and column it was written to.
 *
 * <p>Random nonces make equal plaintexts encrypt differently, so equality search uses a
 * separate blind index: HMAC-SHA256 of the normalised value under a dedicated key.
 */
public final class FieldCipher {
    private final KeyManager keys;

    public FieldCipher(KeyManager keys) {
        this.keys = keys;
    }

    public String encrypt(String plaintext, String context) {
        if (plaintext == null) return null;
        int version = keys.activeVersion();
        byte[] ct = AesGcm.encrypt(keys.dataKey(version), plaintext.getBytes(StandardCharsets.UTF_8),
                context.getBytes(StandardCharsets.UTF_8));
        return "v" + version + ":" + Base64.getEncoder().encodeToString(ct);
    }

    public String decrypt(String stored, String context) {
        if (stored == null) return null;
        int version = versionOf(stored);
        byte[] data = Base64.getDecoder().decode(stored.substring(stored.indexOf(':') + 1));
        byte[] pt = AesGcm.decrypt(keys.dataKey(version), data, context.getBytes(StandardCharsets.UTF_8));
        return new String(pt, StandardCharsets.UTF_8);
    }

    public static int versionOf(String stored) {
        int colon = stored.indexOf(':');
        if (!stored.startsWith("v") || colon < 2) throw new CryptoException("not an encrypted value");
        try {
            return Integer.parseInt(stored.substring(1, colon));
        } catch (NumberFormatException e) {
            throw new CryptoException("bad key version");
        }
    }

    public boolean needsReencryption(String stored) {
        return stored != null && versionOf(stored) != keys.activeVersion();
    }

    /** Deterministic search token for exact-match lookups on an encrypted column. */
    public String blindIndex(String field, String normalizedValue) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keys.indexKey());
            mac.update((field + "\0").getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(mac.doFinal(normalizedValue.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
