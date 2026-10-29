package com.trustgate.core.crypto;

/** Display masking for decrypted personal data (shown to people, never stored). */
public final class Masking {
    private Masking() {}

    /** Resident registration number: digits only, e.g. "9001011234567". */
    public static String normalizeRrn(String rrn) {
        return rrn == null ? null : rrn.replaceAll("[^0-9]", "");
    }

    public static boolean isValidRrn(String rrn) {
        String d = normalizeRrn(rrn);
        return d != null && d.length() == 13;
    }

    /** 900101-1****** : birth date and gender digit stay visible. */
    public static String rrn(String rrn) {
        String d = normalizeRrn(rrn);
        if (d == null || d.length() != 13) return "******-*******";
        return d.substring(0, 6) + "-" + d.charAt(6) + "******";
    }

    public static String normalizePhone(String phone) {
        return phone == null ? null : phone.replaceAll("[^0-9]", "");
    }

    /** 010-****-5678 */
    public static String phone(String phone) {
        String d = normalizePhone(phone);
        if (d == null || d.length() < 8) return "***-****-****";
        return d.substring(0, 3) + "-****-" + d.substring(d.length() - 4);
    }

    /** h***@example.com */
    public static String email(String email) {
        if (email == null) return "";
        int at = email.indexOf('@');
        if (at <= 0) return "***";
        return email.charAt(0) + "***" + email.substring(at);
    }
}
