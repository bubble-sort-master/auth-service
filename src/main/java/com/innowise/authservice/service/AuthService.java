package com.innowise.authservice.service;

import com.innowise.authservice.entity.Role;
import com.innowise.authservice.entity.UserCredentials;
import com.innowise.authservice.exception.DuplicateUsernameException;
import com.innowise.authservice.exception.UserCredentialsNotFoundException;

/**
 * Service interface for authentication business logic.
 * Handles credential storage, password verification and user lookup operations.
 */
public interface AuthService {

  /**
   * Saves user credentials (username, hashed password, role and linked user ID).
   *
   * @param username the username (usually email)
   * @param rawPassword the plain text password (will be hashed)
   * @param role the user's role (USER or ADMIN)
   * @param userId the ID from the main user entity
   * @return the saved UserCredentials entity
   * @throws DuplicateUsernameException if username already exists
   */
  UserCredentials saveCredentials(String username, String rawPassword, Role role, Long userId);

  /**
   * Finds user credentials by username.
   *
   * @param username the username to search for
   * @return the UserCredentials entity
   * @throws UserCredentialsNotFoundException if no credentials found
   */
  UserCredentials findByUsername(String username);

  /**
   * Verifies if the provided raw password matches the stored hashed password.
   *
   * @param rawPassword the password to check
   * @param encodedPassword the stored hashed password
   * @return true if passwords match, false otherwise
   */
  boolean checkPassword(String rawPassword, String encodedPassword);

  /**
   * Finds user credentials by user ID.
   *
   * @param userId the ID of the user
   * @return the UserCredentials entity
   * @throws UserCredentialsNotFoundException if no credentials found for this userId
   */
  UserCredentials findByUserId(Long userId);

  /**
   * Changes the password for a user identified by userId.
   *
   * @param userId         the ID of the user whose password should be changed
   * @param rawNewPassword the new plain text password (will be encoded before storage)
   * @throws UserCredentialsNotFoundException if no credentials exist for the given userId
   */
  void changePassword(Long userId, String rawNewPassword);
}