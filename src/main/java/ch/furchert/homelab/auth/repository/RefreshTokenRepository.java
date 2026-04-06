package ch.furchert.homelab.auth.repository;

import ch.furchert.homelab.auth.entity.RefreshToken;
import ch.furchert.homelab.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByUser(User user);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :cutoff")
    void deleteByExpiresAtBefore(Instant cutoff);
}
