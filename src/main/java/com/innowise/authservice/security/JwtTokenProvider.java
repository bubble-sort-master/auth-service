package com.innowise.authservice.security;

import com.innowise.authservice.config.JwtConfig;
import com.innowise.authservice.entity.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

  private final JwtConfig jwtConfig;
  private final JwtEncoder jwtEncoder;
  private final JwtDecoder jwtDecoder;

  public String generateAccessToken(Long userId, Role role) {
    JwtClaimsSet claims = JwtClaimsSet.builder()
            .subject(userId.toString())
            .claim("role", role.name())
            .claim("token_type", "access")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusMillis(jwtConfig.getAccessTokenExpiration()))
            .build();

    return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }

  public String generateRefreshToken(Long userId, Role role) {
    JwtClaimsSet claims = JwtClaimsSet.builder()
            .subject(userId.toString())
            .claim("role", role.name())
            .claim("token_type", "refresh")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusMillis(jwtConfig.getRefreshTokenExpiration()))
            .build();

    return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }

  public boolean validateToken(String token) {
    try {
      jwtDecoder.decode(token);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  public Long getUserIdFromToken(String token) {
    Jwt jwt = jwtDecoder.decode(token);
    return Long.valueOf(jwt.getSubject());
  }

  public String getRoleFromToken(String token) {
    Jwt jwt = jwtDecoder.decode(token);
    return jwt.getClaimAsString("role");
  }

  public boolean isAccessToken(String token) {
    try {
      Jwt jwt = jwtDecoder.decode(token);
      return "access".equals(jwt.getClaimAsString("token_type"));
    } catch (Exception e) {
      return false;
    }
  }

  public boolean isRefreshToken(String token) {
    try {
      Jwt jwt = jwtDecoder.decode(token);
      return "refresh".equals(jwt.getClaimAsString("token_type"));
    } catch (Exception e) {
      return false;
    }
  }
}