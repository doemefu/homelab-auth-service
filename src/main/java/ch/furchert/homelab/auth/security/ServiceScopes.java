package ch.furchert.homelab.auth.security;

import java.util.Collection;
import java.util.List;

/**
 * Service scopes are issued only through the client_credentials grant (#143): they are refused at
 * the authorization endpoint and for every other grant at the token endpoint. Single source of the
 * list; a new service scope must be added here and to INTERFACES.md §1 "Service scopes".
 */
public final class ServiceScopes {

    private static final List<String> PREFIXES = List.of("netmon:", "analytics:", "login-events:");
    private static final List<String> NAMES = List.of("clients:admin");

    private ServiceScopes() {
    }

    public static boolean isServiceScope(String scope) {
        return scope != null && (NAMES.contains(scope) || PREFIXES.stream().anyMatch(scope::startsWith));
    }

    /** The service scopes contained in {@code scopes}; empty when there are none or {@code scopes} is null. */
    public static List<String> serviceScopesIn(Collection<String> scopes) {
        return scopes == null ? List.of() : scopes.stream().filter(ServiceScopes::isServiceScope).toList();
    }
}
