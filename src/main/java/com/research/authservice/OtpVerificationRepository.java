package com.research.authservice;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

public interface OtpVerificationRepository extends JpaRepository<OtpVerification, Long> {

    Optional<OtpVerification> findTopByEmailAndUsedFalseOrderByCreatedAtDesc(String email);

    @Transactional
    @Modifying
    @Query("UPDATE OtpVerification o SET o.used = true WHERE o.email = :email AND o.used = false")
    void markAllUsedForEmail(String email);

    @Query("SELECT COUNT(o) FROM OtpVerification o WHERE o.email = :email AND o.createdAt >= :since")
    long countRecentByEmail(String email, LocalDateTime since);
}
