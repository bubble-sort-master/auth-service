package com.innowise.authservice.integration;

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
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.title").value("Username Already Exists"))
            .andExpect(jsonPath("$.detail").value("Username already exists: testuser@test.com"))
            .andExpect(jsonPath("$.status").value(409));
  }

  @Test
  void register_invalidData_shouldReturn400() throws Exception {
    String invalidJson = """
                {
                  "username": "",
                  "password": "",
                  "role": "USER",
                  "userId": 100
                }
                """;

    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(invalidJson))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Validation Failed"))
            .andExpect(jsonPath("$.detail").value("One or more fields are invalid"))
            .andExpect(jsonPath("$.errors").isArray())
            .andExpect(jsonPath("$.errors[0]").exists());
  }

  @Test
  void login_success_shouldReturnTokens() throws Exception {
    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());

    mockMvc.perform(post("/auth/token")
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

    mockMvc.perform(post("/auth/token")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(wrongLogin))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Bad Credentials"))
            .andExpect(jsonPath("$.detail").value("Invalid username or password"))
            .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  void login_nonExistentUser_shouldReturn401() throws Exception {
    String nonExistent = """
                {
                  "username": "nonexistent@test.com",
                  "password": "password123"
                }
                """;

    mockMvc.perform(post("/auth/token")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(nonExistent))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Unauthorized"))
            .andExpect(jsonPath("$.detail").value("User not found: nonexistent@test.com"))
            .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  void validate_validToken_shouldReturnTrue() throws Exception {
    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());

    var loginResult = mockMvc.perform(post("/auth/token")
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

  @Test
  void validate_emptyToken_shouldReturnFalse() throws Exception {
    mockMvc.perform(post("/auth/validate")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(""))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(false));
  }

  @Test
  void refresh_validRefreshToken_shouldReturnNewAccessToken() throws Exception {
    mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_REGISTER_JSON))
            .andExpect(status().isOk());

    var loginResult = mockMvc.perform(post("/auth/token")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_LOGIN_JSON))
            .andExpect(status().isOk())
            .andReturn();

    String refreshToken = com.jayway.jsonpath.JsonPath.read(
            loginResult.getResponse().getContentAsString(), "$.refreshToken");

    var refreshResult = mockMvc.perform(post("/auth/refresh")
                    .header("X-Refresh-Token", refreshToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").exists())
            .andExpect(jsonPath("$.refreshToken").exists())
            .andReturn();

    String newAccessToken = com.jayway.jsonpath.JsonPath.read(
            refreshResult.getResponse().getContentAsString(), "$.accessToken");

    mockMvc.perform(post("/auth/validate")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(newAccessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(true))
            .andExpect(jsonPath("$.userId").value(100));
  }

  @Test
  void refresh_invalidRefreshToken_shouldReturn401() throws Exception {
    mockMvc.perform(post("/auth/refresh")
                    .header("X-Refresh-Token", "invalid.token.here"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Invalid Token"))
            .andExpect(jsonPath("$.detail").value("Invalid or expired refresh token"))
            .andExpect(jsonPath("$.status").value(401));
  }
}