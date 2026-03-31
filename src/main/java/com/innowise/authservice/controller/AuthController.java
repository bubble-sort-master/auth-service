package com.innowise.authservice.controller;

import com.innowise.authservice.dto.*;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.BadCredentialsException;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.security.JwtTokenProvider;
import com.innowise.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for authentication and authorization operations.
 * Handles user credential management, login, token refresh and token validation.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final JwtTokenProvider jwtTokenProvider;

  /**
   * Saves user credentials (username, hashed password and role).
   * This endpoint is used during user registration flow  called by API Gateway.
   *
   * @param request contains username, password, role and userId
   * @return HTTP 200 OK on successful save
   */
  @PostMapping("/register")
  public ResponseEntity<Void> register(@Valid @RequestBody CredentialsRequest request) {
    authService.saveCredentials(
            request.username(),
            request.password(),
            Role.USER,
            request.userId()
    );
    return ResponseEntity.ok().build();
  }

  @PostMapping("/admin/register")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<Void> registerAdmin(@Valid @RequestBody AdminCredentialsRequest request) {
    authService.saveCredentials(
            request.username(),
            request.password(),
            request.role(),
            request.userId()
    );
    return ResponseEntity.ok().build();
  }

  /**
   * Authenticates user by username and password.
   * Returns access token and refresh token upon successful authentication.
   *
   * @param request contains username and password
   * @return access and refresh JWT tokens
   * @throws BadCredentialsException if credentials are invalid
   */
  @PostMapping("/token")
  public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
    var credentials = authService.findByUsername(request.username());

    if (!authService.checkPassword(request.password(), credentials.getPassword())) {
      throw new BadCredentialsException("Invalid username or password");
    }

    String accessToken = jwtTokenProvider.generateAccessToken(credentials.getUserId(), credentials.getRole());
    String refreshToken = jwtTokenProvider.generateRefreshToken(credentials.getUserId(), credentials.getRole());

    return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
  }

  /**
   * Refreshes access token using a valid refresh token.
   *
   * @param refreshToken the refresh token passed in X-Refresh-Token header
   * @return new access token and the same refresh token
   * @throws InvalidTokenException if refresh token is invalid or expired
   */
  @PostMapping("/refresh")
  public ResponseEntity<AuthResponse> refresh(@RequestHeader("X-Refresh-Token") String refreshToken) {
    if (!jwtTokenProvider.validateToken(refreshToken) || !jwtTokenProvider.isRefreshToken(refreshToken)) {
      throw new InvalidTokenException("Invalid or expired refresh token");
    }

    Long userId = jwtTokenProvider.getUserIdFromToken(refreshToken);
    var credentials = authService.findByUserId(userId);
    String newAccessToken = jwtTokenProvider.generateAccessToken(userId, credentials.getRole());

    return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshToken));
  }

  /**
   * Validates the provided JWT token.
   *
   * @param token the JWT token to validate (passed in request body as plain text)
   * @return validation result with userId and role if token is valid
   */
  @PostMapping("/validate")
  public ResponseEntity<TokenValidationResponse> validate(@RequestBody(required = false) String token) {
    if (token == null || token.isBlank() ||
            !jwtTokenProvider.validateToken(token) ||
            !jwtTokenProvider.isAccessToken(token)) {
      return ResponseEntity.ok(new TokenValidationResponse(false, null, null));
    }
    Long userId = jwtTokenProvider.getUserIdFromToken(token);
    String role = jwtTokenProvider.getRoleFromToken(token);
    return ResponseEntity.ok(new TokenValidationResponse(true, userId, role));
  }
}