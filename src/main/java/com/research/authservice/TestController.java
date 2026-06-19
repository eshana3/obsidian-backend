package com.research.authservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class TestController {

    @Autowired(required = false)
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/hello")
    public String hello() {
        return "JWT Authentication Working!";
    }

    // Health endpoint — always returns 200 so Render/proxy know the app is up.
    // Also checks DB connectivity and reports it as a sub-status (does not affect HTTP status).
    @RequestMapping(value = "/api/health", method = {RequestMethod.GET, RequestMethod.HEAD})
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "ok");
        body.put("service", "auth-service");

        // Non-blocking DB check — failure is reported but does not make the endpoint return 5xx.
        String dbStatus;
        try {
            if (jdbcTemplate != null) {
                jdbcTemplate.queryForObject("SELECT 1", Integer.class);
                dbStatus = "connected";
            } else {
                dbStatus = "not-configured";
            }
        } catch (Exception e) {
            dbStatus = "unavailable: " + e.getMessage().split("\n")[0];
        }
        body.put("database", dbStatus);
        body.put("timestamp", java.time.Instant.now().toString());

        return ResponseEntity.ok(body);
    }
}