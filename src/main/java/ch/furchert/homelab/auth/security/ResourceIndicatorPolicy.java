package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

/**
 * RFC 8707 resource indicators for clients with configured allowed-resources (docs/080 §4.2).
 * The audience of those clients is hard-mapped in configuration; the received value is only
 * checked, never copied into the token. Clients without a list keep ignoring the parameter.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ResourceIndicatorPolicy {

    public static final String PARAMETER = "resource";
    public static final String INVALID_TARGET = "invalid_target";
    private static final int MAX_LOGGED_LENGTH = 200;

    private final OidcClientProperties properties;

    public boolean isAllowed(RegisteredClient client, Collection<String> resourceValues) {
        String clientId = client.getClientId();
        if (properties.isAudienceBoundWithoutDefinition(client)) {
            // Fail closed: never fall back to "parameter ignored" for a client seeded as audience-bound.
            log.warn("Client '{}' is marked audience-bound but has no configured audience; request rejected", clientId);
            return false;
        }
        List<String> allowed = properties.findClient(clientId)
                .map(OidcClientProperties.ClientDefinition::getAllowedResources)
                .orElse(List.of());
        if (allowed.isEmpty() || resourceValues.isEmpty()) {
            return true;
        }
        for (String value : resourceValues) {
            if (!allowed.contains(value)) {
                // The value is a public URL, logged so a mismatching form can be added to the list (docs/080 O3).
                log.warn("Rejected resource '{}' for client '{}' ({})", sanitise(value), clientId, INVALID_TARGET);
                return false;
            }
        }
        return true;
    }

    public static List<String> values(Object raw) {
        if (raw instanceof String s) {
            return List.of(s);
        }
        if (raw instanceof String[] arr) {
            return List.of(arr);
        }
        return List.of();
    }

    static String sanitise(String value) {
        // \p{Cntrl} is ASCII-only in Java; NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR break lines too.
        String cleaned = value.replaceAll("[\\p{Cntrl}\\u0085\\u2028\\u2029]", "?");
        return cleaned.length() > MAX_LOGGED_LENGTH ? cleaned.substring(0, MAX_LOGGED_LENGTH) + "..." : cleaned;
    }
}
