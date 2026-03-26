package com.innowise.authservice.service;

import com.innowise.authservice.entity.Role;
import com.innowise.authservice.entity.UserCredentials;
import com.innowise.authservice.exception.DuplicateUsernameException;
import com.innowise.authservice.exception.UserCredentialsNotFoundException;
import com.innowise.authservice.repository.UserCredentialsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

  @Mock
  private UserCredentialsRepository repository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @InjectMocks
  private AuthService authService;

  private UserCredentials credentials;

  @BeforeEach
  void setUp() {
    credentials = new UserCredentials();
    credentials.setId(1L);
    credentials.setUsername("test@test.com");
    credentials.setPassword("$2a$12$hashedpassword");
    credentials.setRole(Role.USER);
    credentials.setUserId(100L);
  }

  @Test
  void saveCredentials_success() {
    when(repository.existsByUsername("test@test.com")).thenReturn(false);
    when(passwordEncoder.encode("password123")).thenReturn("$2a$12$hashedpassword");
    when(repository.save(any(UserCredentials.class))).thenReturn(credentials);

    UserCredentials result = authService.saveCredentials("test@test.com", "password123", Role.USER, 100L);

    assertThat(result).isNotNull();
    assertThat(result.getUsername()).isEqualTo("test@test.com");
    verify(repository).save(any(UserCredentials.class));
  }

  @Test
  void saveCredentials_duplicateUsername_throwsException() {
    when(repository.existsByUsername("test@test.com")).thenReturn(true);

    assertThatThrownBy(() -> authService.saveCredentials("test@test.com", "pass", Role.USER, 100L))
            .isInstanceOf(DuplicateUsernameException.class)
            .hasMessageContaining("Username already exists");
  }

  @Test
  void findByUsername_success() {
    when(repository.findByUsername("test@test.com")).thenReturn(Optional.of(credentials));

    UserCredentials result = authService.findByUsername("test@test.com");

    assertThat(result).isEqualTo(credentials);
  }

  @Test
  void findByUsername_notFound_throwsException() {
    when(repository.findByUsername("unknown@test.com")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> authService.findByUsername("unknown@test.com"))
            .isInstanceOf(UserCredentialsNotFoundException.class);
  }

  @Test
  void checkPassword_correctPassword_returnsTrue() {
    when(passwordEncoder.matches("password123", "$2a$12$hashedpassword")).thenReturn(true);

    boolean result = authService.checkPassword("password123", "$2a$12$hashedpassword");

    assertThat(result).isTrue();
  }

  @Test
  void findByUserId_success() {
    when(repository.findByUserId(100L)).thenReturn(Optional.of(credentials));

    UserCredentials result = authService.findByUserId(100L);

    assertThat(result).isEqualTo(credentials);
  }
}