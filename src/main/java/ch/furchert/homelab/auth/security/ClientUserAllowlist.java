package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Owner-only authorization for clients with restrict-to-allowed-users (docs/080 §4.1, D36).
 * Exact, case-sensitive match of each trimmed, non-blank entry with the authenticated username,
 * which is the stored username (lookups are exact) and becomes the token's sub. Fail-closed:
 * an empty list rejects everyone. Applies to authorization requests only, never to refresh.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ClientUserAllowlist {

    private final OidcClientProperties properties;

    public boolean permits(RegisteredClient client, String username) {
        if (properties.isAudienceBoundWithoutDefinition(client)) {
            return false;   // fail closed: a row seeded as audience-bound without its configuration
        }
        OidcClientProperties.ClientDefinition def = properties.findClient(client.getClientId()).orElse(null);
        if (def == null || !def.isRestrictToAllowedUsers()) {
            return true;
        }
        return username != null && entries(def).contains(username);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warnIfUnconfigured() {
        properties.getClients().stream()
                .filter(OidcClientProperties.ClientDefinition::isRestrictToAllowedUsers)
                .filter(def -> entries(def).isEmpty())
                .forEach(def -> log.warn("Client '{}' has no allowed users configured; "
                        + "every authorization request for it is rejected", def.getClientId()));
    }

    private static List<String> entries(OidcClientProperties.ClientDefinition def) {
        return def.getAllowedUsers().stream().map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
