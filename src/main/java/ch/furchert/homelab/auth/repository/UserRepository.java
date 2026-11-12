package ch.furchert.homelab.auth.repository;

import ch.furchert.homelab.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    /**
     * Replaces the password hash only while it is still {@code oldHash} (compare-and-swap), so a login-time
     * re-encode never overwrites a password that was changed in the meantime. Returns the updated row count.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.passwordHash = :newHash, u.updatedAt = :now "
            + "WHERE u.username = :username AND u.passwordHash = :oldHash")
    int replacePasswordHash(@Param("username") String username, @Param("oldHash") String oldHash,
                            @Param("newHash") String newHash, @Param("now") Instant now);
}
