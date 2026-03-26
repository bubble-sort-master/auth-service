package com.innowise.authservice.dto;

public record TokenValidationResponse(
        boolean valid,
        Long userId,
        String role
) {}