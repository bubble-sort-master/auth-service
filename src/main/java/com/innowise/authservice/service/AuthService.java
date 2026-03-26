package com.innowise.authservice.service;

import com.innowise.authservice.entity.UserCredentials;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.DuplicateUsernameException;
import com.innowise.authservice.exception.UserCredentialsNotFoundException;
import com.innowise.authservice.repository.UserCredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserCredentialsRepository credentialsRepository;
  private final PasswordEncoder passwordEncoder;

  @Transactional
  public UserCredentials saveCredentials(String username, String rawPassword, Role role, Long userId) {
    if (credentialsRepository.existsByUsername(username)) {
      throw new DuplicateUsernameException("Username already exists: " + username);
    }

    UserCredentials credentials = new UserCredentials();
    credentials.setUsername(username);
    credentials.setPassword(passwordEncoder.encode(rawPassword));
    credentials.setRole(role);
    credentials.setUserId(userId);

    return credentialsRepository.save(credentials);
  }

  public UserCredentials findByUsername(String username) {
    return credentialsRepository.findByUsername(username)
            .orElseThrow(() -> new UserCredentialsNotFoundException("User not found: " + username));
  }

  public boolean checkPassword(String rawPassword, String encodedPassword) {
    return passwordEncoder.matches(rawPassword, encodedPassword);
  }

  public UserCredentials findByUserId(Long userId) {
    return credentialsRepository.findByUserId(userId)
            .orElseThrow(() -> new UserCredentialsNotFoundException("Credentials not found for userId: " + userId));
  }
}