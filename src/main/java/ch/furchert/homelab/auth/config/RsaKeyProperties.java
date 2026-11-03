package ch.furchert.homelab.auth.config;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "app.jwt")
@Validated
@Getter
@Setter
public class RsaKeyProperties {

    /**
     * JWK {@code kid} of the signing key (env {@code APP_JWT_KEY_ID}). Never blank (consumers skip keys
     * without a kid) and never reused for a different key.
     */
    @NotBlank
    private String keyId = "auth-service-v1";

    private Resource privateKey;
    private Resource publicKey;
    private long accessTokenExpiry;
    private long refreshTokenExpiry;
}
