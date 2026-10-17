package ch.furchert.homelab.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The bearer-token decoder bean: same signature, but ID tokens are refused (and default validators stay). */
class JwtDecoderIdTokenTest {

    private final JWKSource<SecurityContext> jwkSource = jwkSource();
    // jwtDecoder(..) uses none of the config's injected collaborators.
    private final JwtDecoder decoder = new AuthorizationServerConfig(null, null, null, null, null).jwtDecoder(jwkSource);

    private static JWKSource<SecurityContext> jwkSource() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair kp = gen.generateKeyPair();
            RSAKey key = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                    .privateKey((RSAPrivateKey) kp.getPrivate()).keyID("test").build();
            return new ImmutableJWKSet<>(new JWKSet(key));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String sign(JwtClaimsSet.Builder claims) {
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId("test").build();
        return new NimbusJwtEncoder(jwkSource).encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }

    private static JwtClaimsSet.Builder base(Instant now) {
        return JwtClaimsSet.builder().issuer("https://auth.test").subject("admin").audience(List.of("furchert-ch"))
                .issuedAt(now).expiresAt(now.plusSeconds(900)).claim("role", "ADMIN");
    }

    @Test
    void acceptsAnAccessToken() {
        Instant now = Instant.now();
        String token = sign(base(now).notBefore(now).claim("scope", List.of("openid", "profile")));
        assertThat(decoder.decode(token).getClaimAsString("role")).isEqualTo("ADMIN");
    }

    @Test
    void rejectsAnIdTokenWithTheSameSignatureAndRole() {
        Instant now = Instant.now();
        String token = sign(base(now).claim("azp", "furchert-ch").claim("sid", "s").claim("auth_time", now.getEpochSecond()));
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtValidationException.class)
                .hasMessageContaining("ID tokens are not accepted");
    }

    @Test
    void stillRejectsExpiredAccessTokens() {
        Instant past = Instant.now().minusSeconds(3600);
        String token = sign(base(past).notBefore(past).expiresAt(past.plusSeconds(60)));
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtValidationException.class);
    }
}
