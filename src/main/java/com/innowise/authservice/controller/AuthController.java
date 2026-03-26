package com.innowise.authservice.controller;

import com.innowise.authservice.dto.*;
import com.innowise.authservice.exception.BadCredentialsException;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.security.JwtTokenProvider;
import com.innowise.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final JwtTokenProvider jwtTokenProvider;

  @PostMapping("/register")
  public ResponseEntity<Void> register(@Valid @RequestBody CredentialsRequest request) {
    authService.saveCredentials(
            request.username(),
            request.password(),
            request.role(),
            request.userId()
    );
    return ResponseEntity.ok().build();
  }

  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
    var credentials = authService.findByUsername(request.username());

    if (!authService.checkPassword(request.password(), credentials.getPassword())) {
      throw new BadCredentialsException("Invalid username or password");
    }

    String accessToken = jwtTokenProvider.generateAccessToken(credentials.getUserId(), credentials.getRole());
    String refreshToken = jwtTokenProvider.generateRefreshToken(credentials.getUserId());

    return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
  }

  @PostMapping("/refresh")
  public ResponseEntity<AuthResponse> refresh(@RequestHeader("X-Refresh-Token") String refreshToken) {
    if (!jwtTokenProvider.validateToken(refreshToken)) {
      throw new InvalidTokenException("Invalid or expired refresh token");
    }

    Long userId = jwtTokenProvider.getUserIdFromToken(refreshToken);
    var credentials = authService.findByUserId(userId);

    String newAccessToken = jwtTokenProvider.generateAccessToken(userId, credentials.getRole());

    return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshToken));
  }

  @PostMapping("/validate")
  public ResponseEntity<TokenValidationResponse> validate(@RequestBody String token) {
    if (token == null || token.isBlank() || !jwtTokenProvider.validateToken(token)) {
      return ResponseEntity.ok(new TokenValidationResponse(false, null, null));
    }

    Long userId = jwtTokenProvider.getUserIdFromToken(token);
    String role = jwtTokenProvider.getRoleFromToken(token);

    return ResponseEntity.ok(new TokenValidationResponse(true, userId, role));
  }
}