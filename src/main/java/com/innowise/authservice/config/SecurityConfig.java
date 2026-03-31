package com.innowise.authservice.config;

import com.innowise.authservice.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtConfig jwtConfig;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter) throws Exception {
    http
            .securityMatcher("/auth/**")
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/auth/register", "/auth/token", "/auth/refresh", "/auth/validate").permitAll()
                    .anyRequest().authenticated()
            )
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
  }

  @Bean
  @ConditionalOnMissingBean(JwtDecoder.class)
  public JwtDecoder jwtDecoder() {
    SecretKeySpec secretKey = new SecretKeySpec(
            jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
    );
    return NimbusJwtDecoder.withSecretKey(secretKey).build();
  }

  @Bean
  @ConditionalOnMissingBean(JwtEncoder.class)
  public JwtEncoder jwtEncoder() {
    SecretKeySpec secretKey = new SecretKeySpec(
            jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
    );

    var jwk = new com.nimbusds.jose.jwk.OctetSequenceKey.Builder(secretKey)
            .keyID("auth-service-key")
            .algorithm(com.nimbusds.jose.JWSAlgorithm.HS256)
            .build();

    var jwkSet = new com.nimbusds.jose.jwk.JWKSet(jwk);

    return new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(jwkSet));
  }
}