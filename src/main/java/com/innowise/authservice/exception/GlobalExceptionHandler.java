package com.innowise.authservice.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.net.URI;
import java.time.Instant;
import java.util.List;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  private ProblemDetail createProblemDetail(HttpStatus status, String title, String detail, WebRequest request) {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    problem.setTitle(title);
    problem.setInstance(URI.create(request.getDescription(false).replace("uri=", "")));
    problem.setProperty("timestamp", Instant.now());
    return problem;
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<ProblemDetail> handleBadCredentials(BadCredentialsException ex, WebRequest request) {
    log.warn("Bad credentials attempt: {}", ex.getMessage());
    ProblemDetail problem = createProblemDetail(HttpStatus.UNAUTHORIZED,
            "Bad Credentials", ex.getMessage(), request);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
  }

  @ExceptionHandler(InvalidTokenException.class)
  public ResponseEntity<ProblemDetail> handleInvalidToken(InvalidTokenException ex, WebRequest request) {
    log.warn("Invalid token: {}", ex.getMessage());
    ProblemDetail problem = createProblemDetail(HttpStatus.UNAUTHORIZED,
            "Invalid Token", ex.getMessage(), request);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
  }

  @ExceptionHandler(DuplicateUsernameException.class)
  public ResponseEntity<ProblemDetail> handleDuplicateUsername(DuplicateUsernameException ex, WebRequest request) {
    log.warn("Duplicate username: {}", ex.getMessage());
    ProblemDetail problem = createProblemDetail(HttpStatus.CONFLICT,
            "Username Already Exists", ex.getMessage(), request);
    return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
  }

  @ExceptionHandler(UserCredentialsNotFoundException.class)
  public ResponseEntity<ProblemDetail> handleUserCredentialsNotFound(UserCredentialsNotFoundException ex, WebRequest request) {
    log.warn("Credentials not found: {}", ex.getMessage());
    ProblemDetail problem = createProblemDetail(HttpStatus.UNAUTHORIZED,
            "Unauthorized", ex.getMessage(), request);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
  }

  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ProblemDetail> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
    log.warn("Authentication failed: {}", ex.getMessage(), ex);
    ProblemDetail problem = createProblemDetail(HttpStatus.UNAUTHORIZED,
            "Unauthorized", "Authentication failed", request);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ProblemDetail> handleValidation(MethodArgumentNotValidException ex, WebRequest request) {
    log.info("Validation failed");
    ProblemDetail problem = createProblemDetail(HttpStatus.BAD_REQUEST,
            "Validation Failed", "One or more fields are invalid", request);

    List<String> errors = ex.getBindingResult().getFieldErrors().stream()
            .map(err -> err.getField() + ": " + err.getDefaultMessage())
            .toList();

    problem.setProperty("errors", errors);
    return ResponseEntity.badRequest().body(problem);
  }

  @ExceptionHandler(AuthorizationDeniedException.class)
  public ResponseEntity<ProblemDetail> handleAuthorizationDenied(AuthorizationDeniedException ex) {
    ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
    problem.setTitle("Access Denied");
    problem.setDetail("You do not have permission to access this resource");
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ProblemDetail> handleAllExceptions(Exception ex, WebRequest request) {
    log.error("Unexpected error occurred", ex);
    ProblemDetail problem = createProblemDetail(HttpStatus.INTERNAL_SERVER_ERROR,
            "Internal Server Error", "An unexpected error occurred", request);
    return ResponseEntity.internalServerError().body(problem);
  }
}
