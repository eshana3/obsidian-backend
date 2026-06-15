package com.research.assistant.service;
import com.research.assistant.model.User;
import com.research.assistant.repository.UserRepository;
import com.research.assistant.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.*;
@Service
public class AuthService {
    @Autowired private UserRepository userRepository;
    @Autowired private JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    public Map<String,Object> register(String name, String email, String password) {
        Map<String,Object> result = new HashMap<>();
        if (userRepository.existsByEmail(email)) { result.put("success",false); result.put("message","Email already exists."); return result; }
        if (password == null || password.length() < 8) { result.put("success",false); result.put("message","Password must be at least 8 characters."); return result; }
        User user = new User(name.trim(), email.toLowerCase().trim(), passwordEncoder.encode(password));
        userRepository.save(user);
        result.put("success",true); result.put("message","Account created successfully!"); return result;
    }
    public Map<String,Object> login(String email, String password) {
        Map<String,Object> result = new HashMap<>();
        Optional<User> userOpt = userRepository.findByEmail(email.toLowerCase().trim());
        if (userOpt.isEmpty() || !passwordEncoder.matches(password, userOpt.get().getPasswordHash())) {
            result.put("success",false); result.put("message","Invalid email or password."); return result;
        }
        User user = userOpt.get();
        String token = jwtUtil.generateToken(user.getEmail());
        result.put("success",true); result.put("token",token); result.put("access_token",token);
        result.put("name",user.getName()); result.put("email",user.getEmail()); result.put("id",user.getId());
        return result;
    }
    public Map<String,Object> getProfile(String email) {
        Map<String,Object> result = new HashMap<>();
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) { result.put("success",false); result.put("message","User not found."); return result; }
        User user = userOpt.get();
        result.put("id",user.getId()); result.put("name",user.getName()); result.put("email",user.getEmail());
        result.put("role",user.getRole()); result.put("createdAt",user.getCreatedAt()); return result;
    }
}
