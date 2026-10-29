package com.trustgate.core.db;

import java.time.Instant;

/** A TG_USERS row as stored: personal data fields are still ciphertext here. */
public record User(
        long id,
        String username,
        String passwordHash,
        String displayName,
        String role,
        String email,
        String rrnEnc,
        String phoneEnc,
        String otpSecretEnc,
        boolean otpEnabled,
        Long otpLastStep,
        int failedCount,
        Instant lockedUntil,
        Instant createdAt) {

    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_USER = "USER";

    public boolean isAdmin() {
        return ROLE_ADMIN.equals(role);
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }
}
