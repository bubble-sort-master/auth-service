package com.innowise.authservice.dto;

import com.innowise.authservice.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record AdminCredentialsRequest(
        @NotBlank String username,
        @NotBlank String password,
        @NotNull Role role,
        @NotNull Long userId
) {}