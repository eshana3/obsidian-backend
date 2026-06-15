package com.research.assistant.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.*;
import org.springframework.web.filter.CorsFilter;
import java.util.*;

@Configuration
public class CorsConfig {

    // Set CORS_ALLOWED_ORIGINS in Render env vars to add more origins.
    // Default covers: local dev ports, the Node proxy, and the production frontend.
    @Value("${CORS_ALLOWED_ORIGINS:}")
    private String extraOrigins;

    @Bean
    public CorsFilter corsFilter() {
        List<String> origins = new ArrayList<>(Arrays.asList(
            // Local development
            "http://localhost:3000",
            "http://localhost:3001",
            "http://localhost:8080",
            "http://localhost:5500",
            "http://127.0.0.1:5500",
            "http://localhost:63342",
            // Production frontend on Render
            "https://obsidian-frontend-ywof.onrender.com",
            // file:// pages send Origin: null
            "null"
        ));

        // Allow extra origins from env var (comma-separated)
        if (extraOrigins != null && !extraOrigins.isBlank()) {
            for (String o : extraOrigins.split(",")) {
                String trimmed = o.trim();
                if (!trimmed.isEmpty()) origins.add(trimmed);
            }
        }

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(Arrays.asList(
            "Authorization", "Content-Type", "Accept",
            "Origin", "X-Requested-With"
        ));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
