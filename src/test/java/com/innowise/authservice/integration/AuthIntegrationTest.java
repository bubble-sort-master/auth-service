package com.innowise.authservice.integration;

import com.innowise.authservice.dto.AuthRequest;
import com.innowise.authservice.dto.CredentialsRequest;
import com.innowise.authservice.entity.Role;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthIntegrationTest extends AbstractIntegrationTest {

  private static final String VALID_REGISTER_JSON = """
            {
              "username": "testuser@test.com",
              "password": "StrongPass123!",
              "role": "USER",
              "userId": 100
            }
            """;

  private static final String VALID_LOGIN_JSON = """
            {
              "username": "testuser@test.com",
              "password": "StrongPass123!"
            }
            """;

  @Test
  void register_shouldSaveCredentials() throws Exception {
    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());
  }

  @Test
  void register_duplicateUsername_shouldReturn409() throws Exception {
    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());

    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isConflict());
  }

  @Test
  void login_success_shouldReturnTokens() throws Exception {

    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());

    mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_LOGIN_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").exists())
            .andExpect(jsonPath("$.refreshToken").exists());
  }

  @Test
  void login_wrongPassword_shouldReturn401() throws Exception {
    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());

    String wrongLogin = """
                {
                  "username": "testuser@test.com",
                  "password": "WrongPassword123!"
                }
                """;

    mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(wrongLogin))
            .andExpect(status().isUnauthorized());
  }

  @Test
  void login_nonExistentUser_shouldReturn401() throws Exception {
    String nonExistent = """
                {
                  "username": "nonexistent@test.com",
                  "password": "password123"
                }
                """;

    mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(nonExistent))
            .andExpect(status().isUnauthorized());
  }

  @Test
  void validate_validToken_shouldReturnTrue() throws Exception {

    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());

    var loginResult = mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_LOGIN_JSON))
            .andExpect(status().isOk())
            .andReturn();

    String accessToken = com.jayway.jsonpath.JsonPath.read(
            loginResult.getResponse().getContentAsString(), "$.accessToken");

    mockMvc.perform(post("/auth/validate")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(true))
            .andExpect(jsonPath("$.userId").value(100));
  }

  @Test
  void validate_invalidToken_shouldReturnFalse() throws Exception {
    mockMvc.perform(post("/auth/validate")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content("invalid.token.here"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(false));
  }
}