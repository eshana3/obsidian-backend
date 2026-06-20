package com.research.authservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Autowired
    private RefreshTokenRepository refreshTokenRepo;

    @Value("${refresh-token.duration-days:30}")
    private int durationDays;

    @Value("${refresh-token.duration-session-hours:24}")
    private int durationSessionHours;

    public String generateRefreshToken(User user, boolean rememberMe,
                                       String ipAddress, String deviceInfo) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String hash = sha256(rawToken);

        LocalDateTime expiry = rememberMe
            ? LocalDateTime.now().plusDays(durationDays)
            : LocalDateTime.now().plusHours(durationSessionHours);

        RefreshToken rt = new RefreshToken();
        rt.setUser(user);
        rt.setTokenHash(hash);
        rt.setExpiresAt(expiry);
        rt.setIpAddress(ipAddress);
        rt.setDeviceInfo(deviceInfo != null ? deviceInfo.substring(0, Math.min(deviceInfo.length(), 499)) : null);
        refreshTokenRepo.save(rt);

        log.info("Refresh token issued for user {} (rememberMe={})", user.getEmail(), rememberMe);
        return rawToken;
    }

    public Optional<User> validateAndRotate(String rawToken,
                                            String ipAddress, String deviceInfo) {
        String hash = sha256(rawToken);
        Optional<RefreshToken> opt = refreshTokenRepo.findByTokenHashAndRevokedFalse(hash);

        if (opt.isEmpty()) {
            log.warn("Refresh token not found or already revoked");
            return Optional.empty();
        }

        RefreshToken rt = opt.get();
        if (rt.isExpired()) {
            rt.setRevoked(true);
            refreshTokenRepo.save(rt);
            log.warn("Refresh token expired for user {}", rt.getUser().getEmail());
            return Optional.empty();
        }

        // Revoke old token (rotation — each refresh issues a new token)
        rt.setRevoked(true);
        refreshTokenRepo.save(rt);
        log.info("Refresh token rotated for user {}", rt.getUser().getEmail());
        return Optional.of(rt.getUser());
    }

    public void revokeAllForUser(Long userId) {
        refreshTokenRepo.revokeAllForUser(userId);
        log.info("All refresh tokens revoked for user {}", userId);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(64);
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }
}
