package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.dto.CreateUserRequest;
import ch.furchert.homelab.auth.dto.ResetPasswordRequest;
import ch.furchert.homelab.auth.dto.UpdateUserRequest;
import ch.furchert.homelab.auth.dto.UserResponse;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.exception.ResourceNotFoundException;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private User existingUser;

    @BeforeEach
    void setUp() {
        existingUser = new User();
        existingUser.setId(1L);
        existingUser.setUsername("testuser");
        existingUser.setEmail("test@example.com");
        existingUser.setPasswordHash("$2a$12$hash");
        existingUser.setRole(Role.USER);
        existingUser.setStatus("ACTIVE");
    }

    @Test
    void createUser_withValidRequest_returnsUserResponse() {
        CreateUserRequest request = new CreateUserRequest("newuser", "new@example.com", "password123", null);
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("$2a$12$encoded");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(2L);
            return u;
        });

        UserResponse response = userService.createUser(request);

        assertThat(response.username()).isEqualTo("newuser");
        assertThat(response.role()).isEqualTo("USER");
    }

    @Test
    void createUser_withDuplicateUsername_throwsIllegalArgument() {
        CreateUserRequest request = new CreateUserRequest("testuser", "new@example.com", "password123", null);
        when(userRepository.existsByUsername("testuser")).thenReturn(true);

        assertThatThrownBy(() -> userService.createUser(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username already taken");
    }

    @Test
    void createUser_withDuplicateEmail_throwsIllegalArgument() {
        CreateUserRequest request = new CreateUserRequest("newuser", "test@example.com", "password123", null);
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        assertThatThrownBy(() -> userService.createUser(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Email already registered");
    }

    @Test
    void getUser_asAdmin_returnsAnyUser() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));

        UserResponse response = userService.getUser(1L, "otheradmin", true);

        assertThat(response.username()).isEqualTo("testuser");
    }

    @Test
    void getUser_asOwnUser_returnsOwnProfile() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));

        UserResponse response = userService.getUser(1L, "testuser", false);

        assertThat(response.username()).isEqualTo("testuser");
    }

    @Test
    void getUser_asOtherUser_throwsAccessDenied() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));

        assertThatThrownBy(() -> userService.getUser(1L, "otheruser", false))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void getUser_whenNotFound_throwsResourceNotFound() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getUser(99L, "admin", true))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void updateUser_withNewUsername_updatesSuccessfully() {
        UpdateUserRequest request = new UpdateUserRequest("updateduser", null, null, null);
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByUsername("updateduser")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(existingUser);

        UserResponse response = userService.updateUser(1L, request);

        assertThat(response).isNotNull();
        verify(userRepository).save(any(User.class));
    }

    @Test
    void updateUser_withEmailOnly_updatesSuccessfully() {
        UpdateUserRequest request = new UpdateUserRequest(null, "new@example.com", null, null);
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(existingUser);

        userService.updateUser(1L, request);

        verify(userRepository).save(any(User.class));
    }

    @Test
    void deleteUser_whenExists_deletesSuccessfully() {
        when(userRepository.existsById(1L)).thenReturn(true);

        userService.deleteUser(1L);

        verify(userRepository).deleteById(1L);
    }

    @Test
    void deleteUser_whenNotFound_throwsResourceNotFound() {
        when(userRepository.existsById(99L)).thenReturn(false);

        assertThatThrownBy(() -> userService.deleteUser(99L))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void resetPassword_asAdmin_doesNotRequireCurrentPassword() {
        ResetPasswordRequest request = new ResetPasswordRequest(null, "newpassword123");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.encode("newpassword123")).thenReturn("$2a$12$newhash");
        when(userRepository.save(any(User.class))).thenReturn(existingUser);

        userService.resetPassword(1L, request, "admin", true);

        verify(passwordEncoder).encode("newpassword123");
        verify(userRepository).save(existingUser);
    }

    @Test
    void resetPassword_asSelf_requiresCorrectCurrentPassword() {
        ResetPasswordRequest request = new ResetPasswordRequest("oldpassword", "newpassword123");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches("oldpassword", "$2a$12$hash")).thenReturn(true);
        when(passwordEncoder.encode("newpassword123")).thenReturn("$2a$12$newhash");
        when(userRepository.save(any(User.class))).thenReturn(existingUser);

        userService.resetPassword(1L, request, "testuser", false);

        verify(passwordEncoder).encode("newpassword123");
    }

    @Test
    void resetPassword_asSelf_withWrongCurrentPassword_throwsIllegalArgument() {
        ResetPasswordRequest request = new ResetPasswordRequest("wrongpassword", "newpassword123");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> userService.resetPassword(1L, request, "testuser", false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Current password is incorrect");
    }

    @Test
    void resetPassword_asSelf_withoutCurrentPassword_throwsIllegalArgument() {
        ResetPasswordRequest request = new ResetPasswordRequest(null, "newpassword123");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));

        assertThatThrownBy(() -> userService.resetPassword(1L, request, "testuser", false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Current password is required");
    }

    @Test
    void resetPassword_asAdmin_savesNewPasswordHash() {
        ResetPasswordRequest request = new ResetPasswordRequest(null, "newpassword123");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.encode("newpassword123")).thenReturn("$2a$12$newhash");
        when(userRepository.save(any(User.class))).thenReturn(existingUser);

        userService.resetPassword(1L, request, "admin", true);

        verify(userRepository).save(existingUser);
    }

}
