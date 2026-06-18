package com.research.authservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import java.util.Map;

@RestController
public class TestController {

    @GetMapping("/hello")
    public String hello() {
        return "JWT Authentication Working!";
    }

    // Health endpoint for proxy and Render health checks.
    // Mapped under /api/health so the Node proxy (GET /api/spring/health → GET /api/health) works.
    // Also accepts HEAD so Render's own uptime monitor doesn't log 405 warnings.
    @RequestMapping(value = "/api/health", method = {RequestMethod.GET, RequestMethod.HEAD})
    public Map<String, String> health() {
        return Map.of("status", "ok", "service", "auth-service");
    }
}