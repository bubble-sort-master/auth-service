package com.innowise.authservice.exception;

public class UserCredentialsNotFoundException extends RuntimeException {
  public UserCredentialsNotFoundException(String message) {
    super(message);
  }
}