package com.research.assistant.model;
import jakarta.persistence.*;
import java.time.LocalDateTime;
@Entity
@Table(name = "users")
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    @Column(nullable = false) private String name;
    @Column(nullable = false, unique = true) private String email;
    @Column(name = "password_hash", nullable = false) private String passwordHash;
    @Column(name = "created_at") private LocalDateTime createdAt;
    @Column(nullable = false) private String role = "USER";
    @PrePersist protected void onCreate() { createdAt = LocalDateTime.now(); }
    public User() {}
    public User(String name, String email, String passwordHash) { this.name=name; this.email=email; this.passwordHash=passwordHash; }
    public Long getId() { return id; } public void setId(Long id) { this.id=id; }
    public String getName() { return name; } public void setName(String name) { this.name=name; }
    public String getEmail() { return email; } public void setEmail(String email) { this.email=email; }
    public String getPasswordHash() { return passwordHash; } public void setPasswordHash(String h) { this.passwordHash=h; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public String getRole() { return role; } public void setRole(String role) { this.role=role; }
}
