package com.trustgate.idp;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Which service providers received a token for each SSO session, for single logout. */
public final class SsoRegistry {
    private final Map<String, Set<String>> clientsBySid = new ConcurrentHashMap<>();

    public void add(String sid, String clientId) {
        clientsBySid.computeIfAbsent(sid, k -> ConcurrentHashMap.newKeySet()).add(clientId);
    }

    public Set<String> remove(String sid) {
        Set<String> s = clientsBySid.remove(sid);
        return s == null ? Set.of() : s;
    }

    public Set<String> clients(String sid) {
        return clientsBySid.getOrDefault(sid, Set.of());
    }
}
