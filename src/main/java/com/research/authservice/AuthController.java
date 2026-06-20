package com.research.authservice;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private OtpService otpService;
    @Autowired private RefreshTokenService refreshTokenService;

    // ── Legacy password register (backward compat) ────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        if (userRepository.findByEmail(req.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already registered"));
        }
        User user = new User();
        user.setName(req.getName());
        user.setEmail(req.getEmail());
        user.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        user.setProvider("local");
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "Account created successfully"));
    }

    // ── Legacy password login (backward compat) ───────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        User user = userRepository.findByEmail(req.getEmail()).orElse(null);
        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email not registered"));
        }
        if (user.getPasswordHash() == null
                || !passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid credentials"));
        }
        String token = jwtUtil.generateToken(user.getEmail());
        Map<String, Object> resp = new HashMap<>();
        resp.put("access_token", token);
        resp.put("token", token);
        resp.put("name", user.getName());
        resp.put("email", user.getEmail());
        return ResponseEntity.ok(resp);
    }

    // ── OTP: send code ────────────────────────────────────────────────────────
    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String name  = body.get("name");
        String mode  = body.getOrDefault("mode", "login");

        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }
        String normalizedEmail = email.trim().toLowerCase();

        if ("login".equals(mode)) {
            boolean exists = userRepository.findByEmail(normalizedEmail).isPresent();
            if (!exists) {
                return ResponseEntity.status(404).body(Map.of(
                    "error", "Email not registered. Please sign up first.",
                    "notRegistered", true
                ));
            }
        }

        try {
            String userName = (name != null && !name.isBlank()) ? name
                : userRepository.findByEmail(normalizedEmail).map(User::getName).orElse(null);
            otpService.sendOtp(normalizedEmail, userName);
            return ResponseEntity.ok(Map.of("status", "sent",
                "message", "Verification code sent to " + email));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ── OTP: verify and authenticate ──────────────────────────────────────────
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> body,
                                       HttpServletRequest request) {
        String email     = body.get("email");
        String otp       = body.get("otp");
        String name      = body.get("name");
        boolean remember = "true".equalsIgnoreCase(body.get("rememberMe"));

        if (email == null || otp == null || email.isBlank() || otp.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email and OTP are required"));
        }
        String normalizedEmail = email.trim().toLowerCase();

        OtpService.OtpVerificationResult result = otpService.verifyOtp(normalizedEmail, otp.trim());
        if (!result.success()) {
            return ResponseEntity.badRequest().body(Map.of("error", result.error()));
        }

        final String resolvedName = (name != null && !name.isBlank())
            ? name : normalizedEmail.split("@")[0];

        User user = userRepository.findByEmail(normalizedEmail).orElseGet(() -> {
            User u = new User();
            u.setEmail(normalizedEmail);
            u.setName(resolvedName);
            u.setProvider("local");
            u.setEmailVerified(true);
            u.setCreatedAt(LocalDateTime.now());
            return userRepository.save(u);
        });

        user.setEmailVerified(true);
        userRepository.save(user);

        String jwt          = jwtUtil.generateToken(user.getEmail());
        String refreshToken = refreshTokenService.generateRefreshToken(
            user, remember,
            request.getRemoteAddr(),
            request.getHeader("User-Agent")
        );

        Map<String, Object> resp = new HashMap<>();
        resp.put("access_token", jwt);
        resp.put("token", jwt);
        resp.put("refresh_token", refreshToken);
        resp.put("name", user.getName());
        resp.put("email", user.getEmail());
        return ResponseEntity.ok(resp);
    }

    // ── Refresh access token ──────────────────────────────────────────────────
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body,
                                     HttpServletRequest request) {
        String rawToken = body.get("refreshToken");
        if (rawToken == null || rawToken.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "No refresh token provided"));
        }

        Optional<User> userOpt = refreshTokenService.validateAndRotate(
            rawToken, request.getRemoteAddr(), request.getHeader("User-Agent")
        );

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).body(
                Map.of("error", "Session expired. Please sign in again."));
        }

        User user = userOpt.get();
        String newJwt     = jwtUtil.generateToken(user.getEmail());
        String newRefresh = refreshTokenService.generateRefreshToken(
            user, true,
            request.getRemoteAddr(),
            request.getHeader("User-Agent")
        );

        return ResponseEntity.ok(Map.of(
            "access_token", newJwt,
            "token", newJwt,
            "refresh_token", newRefresh
        ));
    }

    // ── Profile ───────────────────────────────────────────────────────────────
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) return ResponseEntity.status(401).build();
        Map<String, Object> resp = new HashMap<>();
        resp.put("name", user.getName());
        resp.put("email", user.getEmail());
        resp.put("provider", user.getProvider());
        resp.put("emailVerified", user.isEmailVerified());
        if (user.getAvatarUrl() != null) resp.put("avatarUrl", user.getAvatarUrl());
        return ResponseEntity.ok(resp);
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> body) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) return ResponseEntity.status(401).build();
        if (body.containsKey("name") && body.get("name") != null && !body.get("name").isBlank()) {
            user.setName(body.get("name"));
        }
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("name", user.getName(), "email", user.getEmail()));
    }

    // ── Logout ────────────────────────────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody(required = false) Map<String, String> body) {
        if (body != null && body.containsKey("refreshToken")) {
            try {
                refreshTokenService.validateAndRotate(body.get("refreshToken"), null, null);
            } catch (Exception ignored) {}
        }
        return ResponseEntity.ok(Map.of("message", "Logged out"));
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email).orElse(null);
        if (user != null) refreshTokenService.revokeAllForUser(user.getId());
        return ResponseEntity.ok(Map.of("message", "All sessions revoked"));
    }

    @GetMapping("/oauth2/failure")
    public ResponseEntity<?> oauthFailure() {
        return ResponseEntity.badRequest().body(Map.of("error", "GitHub login failed"));
    }
}
