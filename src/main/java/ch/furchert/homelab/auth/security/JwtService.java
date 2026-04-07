package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.RsaKeyProperties;
import ch.furchert.homelab.auth.entity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final String ISSUER = "homelab-auth-service";
    private static final String CLAIM_ROLE = "role";
    public static final String KEY_ID = "auth-service-v1";

    private final RsaKeyProvider rsaKeyProvider;
    private final RsaKeyProperties rsaKeyProperties;

    public String generateAccessToken(String username, Role role) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .header().keyId(KEY_ID).and()
                .issuer(ISSUER)
                .subject(username)
                .claim(CLAIM_ROLE, role.name())
                .issuedAt(new Date(now))
                .expiration(new Date(now + rsaKeyProperties.getAccessTokenExpiry()))
                .signWith(rsaKeyProvider.getPrivateKey())
                .compact();
    }

    public Claims validateAndParse(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(rsaKeyProvider.getPublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            throw new JwtException("Invalid or expired JWT: " + e.getMessage(), e);
        }
    }

    public String extractUsername(String token) {
        return validateAndParse(token).getSubject();
    }

    public String extractRole(String token) {
        return validateAndParse(token).get(CLAIM_ROLE, String.class);
    }
}
