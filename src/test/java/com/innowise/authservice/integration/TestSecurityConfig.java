package com.innowise.authservice.integration;

import com.innowise.authservice.config.JwtConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@TestConfiguration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class TestSecurityConfig {

  private final JwtConfig jwtConfig;

  @Bean
  @Primary
  public JwtEncoder jwtEncoder() {
    SecretKey key = new SecretKeySpec(
            jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
    );
    return NimbusJwtEncoder.withSecretKey(key).build();
  }

  @Bean
  @Primary
  public JwtDecoder jwtDecoder() {
    SecretKey key = new SecretKeySpec(
            jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
    );
    return NimbusJwtDecoder.withSecretKey(key).build();
  }
}