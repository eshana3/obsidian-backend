package com.research.authservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class OtpService {

    private static final Logger log = LoggerFactory.getLogger(OtpService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Autowired
    private OtpVerificationRepository otpRepo;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${otp.expiry-minutes:5}")
    private int expiryMinutes;

    @Value("${otp.max-attempts:3}")
    private int maxAttempts;

    public void sendOtp(String email, String userName) {
        // Rate-limit: max 5 OTPs per email per 15 minutes
        LocalDateTime since = LocalDateTime.now().minusMinutes(15);
        long recentCount = otpRepo.countRecentByEmail(email, since);
        if (recentCount >= 5) {
            throw new RuntimeException("Too many OTP requests. Please wait before trying again.");
        }

        // Invalidate all previous active OTPs for this email
        otpRepo.markAllUsedForEmail(email);

        // Cryptographically secure 6-digit OTP
        String otp = String.format("%06d", RANDOM.nextInt(1_000_000));
        String hash = passwordEncoder.encode(otp);

        OtpVerification record = new OtpVerification();
        record.setEmail(email);
        record.setOtpHash(hash);
        record.setExpiresAt(LocalDateTime.now().plusMinutes(expiryMinutes));
        record.setCreatedAt(LocalDateTime.now());
        otpRepo.save(record);

        emailService.sendOtp(email, otp, userName);
        log.info("OTP issued for {}", email);
    }

    public OtpVerificationResult verifyOtp(String email, String inputOtp) {
        Optional<OtpVerification> opt =
            otpRepo.findTopByEmailAndUsedFalseOrderByCreatedAtDesc(email);

        if (opt.isEmpty()) {
            return OtpVerificationResult.failure("No active OTP found. Please request a new one.");
        }

        OtpVerification record = opt.get();

        if (record.isExpired()) {
            record.setUsed(true);
            otpRepo.save(record);
            return OtpVerificationResult.failure("OTP has expired. Please request a new one.");
        }

        if (record.getAttempts() >= maxAttempts) {
            record.setUsed(true);
            otpRepo.save(record);
            return OtpVerificationResult.failure("Too many failed attempts. Please request a new OTP.");
        }

        record.setAttempts(record.getAttempts() + 1);

        if (!passwordEncoder.matches(inputOtp, record.getOtpHash())) {
            otpRepo.save(record);
            int remaining = maxAttempts - record.getAttempts();
            if (remaining <= 0) {
                record.setUsed(true);
                otpRepo.save(record);
                return OtpVerificationResult.failure("Invalid code. No attempts remaining — please request a new OTP.");
            }
            return OtpVerificationResult.failure("Invalid code. " + remaining + " attempt(s) remaining.");
        }

        record.setUsed(true);
        otpRepo.save(record);
        log.info("OTP verified successfully for {}", email);
        return OtpVerificationResult.success();
    }

    public record OtpVerificationResult(boolean success, String error) {
        static OtpVerificationResult success() { return new OtpVerificationResult(true, null); }
        static OtpVerificationResult failure(String msg) { return new OtpVerificationResult(false, msg); }
    }
}
