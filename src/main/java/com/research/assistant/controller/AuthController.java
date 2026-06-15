package com.research.assistant.controller;
import com.research.assistant.service.AuthService;
import com.research.assistant.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {
    @Autowired private AuthService authService;
    @Autowired private JwtUtil jwtUtil;
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String,String> req) {
        if (req.get("name")==null||req.get("email")==null||req.get("password")==null)
            return ResponseEntity.badRequest().body(Map.of("message","Name, email and password required."));
        Map<String,Object> result = authService.register(req.get("name"),req.get("email"),req.get("password"));
        return (boolean)result.get("success") ? ResponseEntity.status(201).body(result) : ResponseEntity.badRequest().body(result);
    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> req) {
        if (req.get("email")==null||req.get("password")==null)
            return ResponseEntity.badRequest().body(Map.of("message","Email and password required."));
        Map<String,Object> result = authService.login(req.get("email"),req.get("password"));
        return (boolean)result.get("success") ? ResponseEntity.ok(result) : ResponseEntity.status(401).body(result);
    }
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@RequestHeader(value="Authorization",required=false) String authHeader) {
        String email = extractEmail(authHeader);
        if (email==null) return ResponseEntity.status(401).body(Map.of("message","Invalid or missing token."));
        return ResponseEntity.ok(authService.getProfile(email));
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout() { return ResponseEntity.ok(Map.of("message","Logged out.")); }
    private String extractEmail(String authHeader) {
        if (authHeader==null||!authHeader.startsWith("Bearer ")) return null;
        String token = authHeader.substring(7);
        try { return jwtUtil.validateToken(token) ? jwtUtil.extractEmail(token) : null; } catch(Exception e) { return null; }
    }
}
