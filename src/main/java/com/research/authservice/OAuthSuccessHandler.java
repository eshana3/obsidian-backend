package com.research.authservice;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthSuccessHandler.class);

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Value("${app.frontend-base-url:http://localhost:3001}")
    private String frontendBaseUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();

        String email    = oauthUser.getAttribute("email");
        String name     = oauthUser.getAttribute("name");
        String login    = oauthUser.getAttribute("login");   // GitHub username
        Object idObj    = oauthUser.getAttribute("id");
        String githubId = idObj != null ? String.valueOf(idObj) : null;
        String avatarUrl = oauthUser.getAttribute("avatar_url");

        if (name == null || name.isBlank()) {
            name = (login != null) ? login : "GitHub User";
        }

        if (email == null || email.isBlank()) {
            log.warn("GitHub OAuth: email not provided by user '{}'", login);
            response.sendRedirect(frontendBaseUrl + "/login.html?error=github_no_email");
            return;
        }

        final String resolvedName = name;
        User user = userRepo.findByEmail(email).orElseGet(() -> {
            User u = new User();
            u.setEmail(email);
            u.setName(resolvedName);
            u.setProvider("github");
            u.setGithubId(githubId);
            u.setAvatarUrl(avatarUrl);
            u.setEmailVerified(true);
            u.setCreatedAt(LocalDateTime.now());
            return userRepo.save(u);
        });

        // Link GitHub to existing account if not yet linked
        if (githubId != null && user.getGithubId() == null) {
            user.setGithubId(githubId);
            user.setEmailVerified(true);
            if (avatarUrl != null) user.setAvatarUrl(avatarUrl);
            userRepo.save(user);
        }

        String jwt          = jwtUtil.generateToken(email);
        String ipAddress    = request.getRemoteAddr();
        String userAgent    = request.getHeader("User-Agent");
        String refreshToken = refreshTokenService.generateRefreshToken(user, true, ipAddress, userAgent);

        String redirectUrl = frontendBaseUrl + "/oauth-callback.html"
            + "?token="   + URLEncoder.encode(jwt,          StandardCharsets.UTF_8)
            + "&refresh="  + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8)
            + "&name="     + URLEncoder.encode(user.getName(), StandardCharsets.UTF_8)
            + "&email="    + URLEncoder.encode(email,         StandardCharsets.UTF_8);

        log.info("GitHub OAuth success for {} — redirecting to frontend", email);
        response.sendRedirect(redirectUrl);
    }
}
