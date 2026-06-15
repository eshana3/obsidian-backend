package com.research.authservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest req) {

        User user = new User();

        user.setName(req.getName());
        user.setEmail(req.getEmail());

        String hashed =
                passwordEncoder.encode(req.getPassword());

        user.setPasswordHash(hashed);

        user.setCreatedAt(LocalDateTime.now());

        userRepository.save(user);

        return ResponseEntity.ok("User registered!");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest req) {

        User user = userRepository
                .findByEmail(req.getEmail())
                .orElse(null);

        if (user == null) {
            return ResponseEntity
                    .badRequest()
                    .body("User not found");
        }

        boolean matches =
                passwordEncoder.matches(
                        req.getPassword(),
                        user.getPasswordHash()
                );

        if (!matches) {
            return ResponseEntity
                    .badRequest()
                    .body("Invalid credentials");
        }

        String jwtToken = "dummy-jwt-token";

        return ResponseEntity.ok(
                Map.of(
                        "access_token",
                        jwtToken
                )
        );
    }
}