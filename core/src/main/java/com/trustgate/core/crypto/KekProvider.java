package com.trustgate.core.crypto;

import javax.crypto.SecretKey;

/**
 * Source of the key-encryption key (KEK). Data keys never leave the database unwrapped;
 * only this master key unwraps them.
 *
 * <p>This is the integration point for an external key store: the demo implementation reads a
 * PKCS#12 file, and an HSM or cloud KMS would implement the same two operations without the
 * KEK ever being exported.
 */
public interface KekProvider {
    byte[] wrap(byte[] dataKey, byte[] aad);

    byte[] unwrap(byte[] wrapped, byte[] aad);

    /** Human-readable description for the admin console, without secrets. */
    String describe();
}
