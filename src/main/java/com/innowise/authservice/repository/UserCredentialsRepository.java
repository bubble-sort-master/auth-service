package com.innowise.authservice.repository;

import com.innowise.authservice.entity.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentials, Long> {

  Optional<UserCredentials> findByUsername(String username);

  boolean existsByUsername(String username);

  Optional<UserCredentials> findByUserId(Long userId);
}