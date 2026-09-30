package ch.furchert.homelab.auth.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Consent store of the IdP (#107): Spring Authorization Server's JDBC consent service on
 * oauth2_authorization_consent, made traceable. created_at/updated_at come from Flyway V8;
 * SAS's UPDATE sets only authorities, so every save refreshes updated_at here. One audit line per
 * decision with client id, scopes and action — never the username, a token or a secret.
 */
@RequiredArgsConstructor
@Slf4j
public class AuditingAuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private static final String TOUCH_SQL = "UPDATE oauth2_authorization_consent SET updated_at = now() "
            + "WHERE registered_client_id = ? AND principal_name = ?";

    private final OAuth2AuthorizationConsentService delegate;
    private final JdbcOperations jdbcOperations;
    private final RegisteredClientRepository registeredClientRepository;

    @Override
    @Transactional
    public void save(OAuth2AuthorizationConsent consent) {
        delegate.save(consent);
        jdbcOperations.update(TOUCH_SQL, consent.getRegisteredClientId(), consent.getPrincipalName());
        log.info("Consent saved: client='{}' scopes={}", clientId(consent), consent.getScopes());
    }

    @Override
    @Transactional
    public void remove(OAuth2AuthorizationConsent consent) {
        delegate.remove(consent);
        log.info("Consent removed: client='{}'", clientId(consent));
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        return delegate.findById(registeredClientId, principalName);
    }

    private String clientId(OAuth2AuthorizationConsent consent) {
        RegisteredClient client = registeredClientRepository.findById(consent.getRegisteredClientId());
        return client != null ? client.getClientId() : consent.getRegisteredClientId();
    }
}
