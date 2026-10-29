package com.trustgate.sp;

import java.io.Serializable;
import java.util.List;

/** The signed-in user as this service provider knows them, taken from a verified ID token. */
public record SpUser(String sub, String name, String role, String sid, long authTime, List<?> amr,
                     String idToken, String headerJson, String payloadJson, long loginAt) implements Serializable {
    public static final String ATTR = "user";
}
