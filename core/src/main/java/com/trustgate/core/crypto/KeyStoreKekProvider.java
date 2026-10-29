package com.trustgate.core.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** KEK held in a password-protected PKCS#12 key store file, created on first start. */
public final class KeyStoreKekProvider implements KekProvider {
    private static final String ALIAS = "trustgate-kek";

    private final SecretKey kek;
    private final Path path;

    private KeyStoreKekProvider(SecretKey kek, Path path) {
        this.kek = kek;
        this.path = path;
    }

    public static KeyStoreKekProvider openOrCreate(Path path, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
            if (Files.exists(path)) {
                try (InputStream in = Files.newInputStream(path)) {
                    ks.load(in, password);
                }
                KeyStore.Entry entry = ks.getEntry(ALIAS, protection);
                if (!(entry instanceof KeyStore.SecretKeyEntry ske)) {
                    throw new IllegalStateException("key store has no secret key '" + ALIAS + "'");
                }
                return new KeyStoreKekProvider(ske.getSecretKey(), path);
            }
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(256);
            SecretKey kek = gen.generateKey();
            ks.load(null, password);
            ks.setEntry(ALIAS, new KeyStore.SecretKeyEntry(kek), protection);
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            try (OutputStream out = Files.newOutputStream(path)) {
                ks.store(out, password);
            }
            return new KeyStoreKekProvider(kek, path);
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("cannot open KEK key store " + path + ": " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] wrap(byte[] dataKey, byte[] aad) {
        return AesGcm.encrypt(kek, dataKey, aad);
    }

    @Override
    public byte[] unwrap(byte[] wrapped, byte[] aad) {
        return AesGcm.decrypt(kek, wrapped, aad);
    }

    @Override
    public String describe() {
        return "PKCS#12 key store " + path.getFileName() + " (AES-256, alias " + ALIAS + ")";
    }
}
