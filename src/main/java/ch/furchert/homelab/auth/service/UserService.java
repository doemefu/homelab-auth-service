package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.dto.CreateUserRequest;
import ch.furchert.homelab.auth.dto.ResetPasswordRequest;
import ch.furchert.homelab.auth.dto.UpdateUserRequest;
import ch.furchert.homelab.auth.dto.UserResponse;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.exception.ResourceNotFoundException;
import ch.furchert.homelab.auth.repository.RefreshTokenRepository;
import ch.furchert.homelab.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final java.util.Set<String> VALID_ROLES = java.util.Set.of("USER", "ADMIN");
    private static final java.util.Set<String> VALID_STATUSES = java.util.Set.of("ACTIVE", "INACTIVE");

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already taken: " + request.username());
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered: " + request.email());
        }

        String role = request.role() != null ? request.role() : "USER";
        if (!VALID_ROLES.contains(role)) {
            throw new IllegalArgumentException("Invalid role: " + role);
        }

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(role);

        return UserResponse.from(userRepository.save(user));
    }

    public UserResponse getUser(Long id, String callerUsername, boolean isAdmin) {
        User user = findById(id);
        if (!isAdmin && !user.getUsername().equals(callerUsername)) {
            throw new AccessDeniedException("Access denied");
        }
        return UserResponse.from(user);
    }

    @Transactional
    public UserResponse updateUser(Long id, UpdateUserRequest request) {
        User user = findById(id);
        boolean usernameChanged = false;

        if (request.username() != null && !request.username().equals(user.getUsername())) {
            if (userRepository.existsByUsername(request.username())) {
                throw new IllegalArgumentException("Username already taken: " + request.username());
            }
            user.setUsername(request.username());
            usernameChanged = true;
        }
        if (request.email() != null && !request.email().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.email())) {
                throw new IllegalArgumentException("Email already registered: " + request.email());
            }
            user.setEmail(request.email());
        }
        if (request.role() != null) {
            if (!VALID_ROLES.contains(request.role())) {
                throw new IllegalArgumentException("Invalid role: " + request.role());
            }
            user.setRole(request.role());
        }
        if (request.status() != null) {
            if (!VALID_STATUSES.contains(request.status())) {
                throw new IllegalArgumentException("Invalid status: " + request.status());
            }
            user.setStatus(request.status());
        }

        UserResponse response = UserResponse.from(userRepository.save(user));

        // Invalidate all refresh tokens when username changes — existing JWTs use old username as sub
        if (usernameChanged) {
            refreshTokenRepository.deleteByUser(user);
        }

        return response;
    }

    @Transactional
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("User not found: " + id);
        }
        userRepository.deleteById(id);
    }

    @Transactional
    public void resetPassword(Long id, ResetPasswordRequest request, String callerUsername, boolean isAdmin) {
        User user = findById(id);

        if (!isAdmin) {
            if (!user.getUsername().equals(callerUsername)) {
                throw new AccessDeniedException("Access denied");
            }
            if (request.currentPassword() == null || request.currentPassword().isBlank()) {
                throw new IllegalArgumentException("Current password is required");
            }
            if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
                throw new IllegalArgumentException("Current password is incorrect");
            }
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        // Invalidate all refresh tokens — password change should require re-authentication
        refreshTokenRepository.deleteByUser(user);
    }

    private User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + id));
    }
}
