package com.trustgate.core.crypto;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-256-GCM with a random 96-bit nonce. Output layout: nonce(12) || ciphertext || tag(16).
 * The AAD binds a ciphertext to where it is stored, so a value copied into another row or
 * column fails authentication instead of decrypting.
 */
public final class AesGcm {
    public static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcm() {}

    public static byte[] encrypt(SecretKey key, byte[] plaintext, byte[] aad) {
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null) c.updateAAD(aad);
            byte[] ct = c.doFinal(plaintext);
            return ByteBuffer.allocate(NONCE_BYTES + ct.length).put(nonce).put(ct).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** @throws CryptoException if the data was modified or the key/AAD is wrong */
    public static byte[] decrypt(SecretKey key, byte[] data, byte[] aad) {
        if (data.length < NONCE_BYTES + TAG_BITS / 8) throw new CryptoException("ciphertext too short");
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data, 0, NONCE_BYTES));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(data, NONCE_BYTES, data.length - NONCE_BYTES);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new CryptoException("authentication failed: data modified, wrong key or wrong context");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
