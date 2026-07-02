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
    @Autowired private RefreshTokenService refreshTokenService;

    // ── Register ───────────────────────────────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        if (req.getName() == null || req.getName().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Name is required"));
        }
        if (req.getEmail() == null || req.getEmail().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }
        if (req.getPassword() == null || req.getPassword().length() < 8) {
            return ResponseEntity.badRequest().body(Map.of("error", "Password must be at least 8 characters"));
        }

        String email = req.getEmail().trim().toLowerCase();
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already registered"));
        }

        User user = new User();
        user.setName(req.getName().trim());
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        user.setProvider("local");
        user.setEmailVerified(true);
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Account created successfully"));
    }

    // ── Login ──────────────────────────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body,
                                   HttpServletRequest request) {
        String email    = body.get("email");
        String password = body.get("password");
        boolean remember = "true".equalsIgnoreCase(body.getOrDefault("rememberMe", "false"));

        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email and password are required"));
        }

        User user = userRepository.findByEmail(email.trim().toLowerCase()).orElse(null);
        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid email or password"));
        }
        if (user.getPasswordHash() == null
                || !passwordEncoder.matches(password, user.getPasswordHash())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid email or password"));
        }

        String jwt          = jwtUtil.generateToken(user.getEmail());
        String refreshToken = refreshTokenService.generateRefreshToken(
            user, remember,
            request.getRemoteAddr(),
            request.getHeader("User-Agent")
        );

        Map<String, Object> resp = new HashMap<>();
        resp.put("access_token",  jwt);
        resp.put("token",         jwt);
        resp.put("refresh_token", refreshToken);
        resp.put("name",          user.getName());
        resp.put("email",         user.getEmail());
        return ResponseEntity.ok(resp);
    }

    // ── Refresh access token ───────────────────────────────────────────────────
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

        User user     = userOpt.get();
        String newJwt = jwtUtil.generateToken(user.getEmail());
        String newRefresh = refreshTokenService.generateRefreshToken(
            user, true,
            request.getRemoteAddr(),
            request.getHeader("User-Agent")
        );

        return ResponseEntity.ok(Map.of(
            "access_token",  newJwt,
            "token",         newJwt,
            "refresh_token", newRefresh
        ));
    }

    // ── Profile ────────────────────────────────────────────────────────────────
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) return ResponseEntity.status(401).build();
        Map<String, Object> resp = new HashMap<>();
        resp.put("name",          user.getName());
        resp.put("email",         user.getEmail());
        resp.put("provider",      user.getProvider());
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

    // ── Logout ─────────────────────────────────────────────────────────────────
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
