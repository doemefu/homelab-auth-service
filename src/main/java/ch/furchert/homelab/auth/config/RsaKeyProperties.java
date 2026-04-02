package ch.furchert.homelab.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.jwt")
@Getter
@Setter
public class RsaKeyProperties {

    private Resource privateKey;
    private Resource publicKey;
    private long accessTokenExpiry;
    private long refreshTokenExpiry;
}
