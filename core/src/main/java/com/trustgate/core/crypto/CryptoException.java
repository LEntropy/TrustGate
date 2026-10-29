package com.trustgate.core.crypto;

/** A ciphertext could not be authenticated or decoded. */
public class CryptoException extends RuntimeException {
    public CryptoException(String message) {
        super(message);
    }
}
