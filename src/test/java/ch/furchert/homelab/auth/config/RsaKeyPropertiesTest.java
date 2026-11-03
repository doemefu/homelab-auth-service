package ch.furchert.homelab.auth.config;

import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** #106: the kid defaults to today's value and can never be blank (consumers skip keys without a kid). */
class RsaKeyPropertiesTest {

    @Test
    void kidDefaultsToTodaysValueAndMustNotBeBlank() {
        RsaKeyProperties props = new RsaKeyProperties();
        assertThat(props.getKeyId()).isEqualTo("auth-service-v1");
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            assertThat(factory.getValidator().validate(props)).isEmpty();
            props.setKeyId(" ");
            assertThat(factory.getValidator().validate(props)).extracting(v -> v.getPropertyPath().toString())
                    .containsExactly("keyId");
        }
    }
}
