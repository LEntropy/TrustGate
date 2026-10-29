package com.trustgate.idp;

import java.io.Serializable;
import java.util.List;

/** The IdP-side SSO session: who logged in, when, and with which factors. */
public record SsoSession(long userId, String username, String name, String role, String sid,
                         long authTime, List<String> amr) implements Serializable {
    public static final String ATTR = "sso";
}
