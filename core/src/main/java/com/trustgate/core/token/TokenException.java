package com.trustgate.core.token;

/** A token was rejected. The message says why, for logs and audit (never shown to attackers verbatim). */
public class TokenException extends Exception {
    public TokenException(String message) {
        super(message);
    }
}
