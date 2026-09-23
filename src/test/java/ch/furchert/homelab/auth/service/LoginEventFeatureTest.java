package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import ch.furchert.homelab.auth.config.OidcClientProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LoginEventFeatureTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";

    private static LoginEventFeature feature(String hmacKey, String dataServiceSecret) {
        LoginEventProperties props = new LoginEventProperties();
        props.setHmacKey(hmacKey);
        OidcClientProperties oidc = new OidcClientProperties();
        if (dataServiceSecret != null) {
            OidcClientProperties.ClientDefinition def = new OidcClientProperties.ClientDefinition();
            def.setClientId("data-service");
            def.setClientSecret(dataServiceSecret);
            oidc.getClients().add(def);
        }
        return new LoginEventFeature(props, oidc);
    }

    @Test
    void enabledWhenKeyAndConsumerSecretPresent() {
        assertThat(feature(KEY, "{noop}s").isEnabled()).isTrue();
    }

    @Test
    void disabledWhenKeyMissing() {
        assertThat(feature("", "{noop}s").isEnabled()).isFalse();
        assertThat(feature(null, "{noop}s").isEnabled()).isFalse();
    }

    @Test
    void disabledWhenKeyTooShort() {
        assertThat(feature("short-key", "{noop}s").isEnabled()).isFalse();
    }

    @Test
    void disabledWhenConsumerSecretBlankOrClientAbsent() {
        assertThat(feature(KEY, "").isEnabled()).isFalse();
        assertThat(feature(KEY, null).isEnabled()).isFalse();
    }

    @Test
    void disabledWhenBothMissing() {
        assertThat(feature("", "").isEnabled()).isFalse();
    }
}
