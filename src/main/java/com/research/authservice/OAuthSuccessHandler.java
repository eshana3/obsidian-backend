package com.research.authservice;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;

@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthSuccessHandler.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();

    @Autowired private UserRepository userRepo;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private RefreshTokenService refreshTokenService;
    @Autowired private OAuth2AuthorizedClientService authorizedClientService;

    @Value("${app.frontend-url:http://localhost:3001}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = oauthToken.getPrincipal();

        String login     = oauthUser.getAttribute("login");      // GitHub username
        String name      = oauthUser.getAttribute("name");
        Object idObj     = oauthUser.getAttribute("id");
        String githubId  = idObj != null ? String.valueOf(idObj) : null;
        String avatarUrl = oauthUser.getAttribute("avatar_url");
        String email     = oauthUser.getAttribute("email");      // null when email is private

        if (name == null || name.isBlank()) {
            name = (login != null && !login.isBlank()) ? login : "GitHub User";
        }

        log.info("GitHub OAuth: login='{}' name='{}' profileEmail='{}'",
            login, name, email != null ? email : "(private)");

        // Most GitHub users have private email — profile returns null.
        // Fall back to the /user/emails API which always returns verified emails.
        if (email == null || email.isBlank()) {
            log.info("GitHub OAuth: profile email absent for '{}' — calling /user/emails", login);
            email = fetchPrimaryEmailFromGitHub(oauthToken);
        }

        if (email == null || email.isBlank()) {
            log.warn("GitHub OAuth: no verified email found for login='{}' — redirecting to error", login);
            String redirectUrl = frontendUrl + "/login.html?error=github_no_email";
            log.info("GitHub OAuth → failure redirect: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
            return;
        }

        final String resolvedEmail = email.trim().toLowerCase();
        final String resolvedName  = name;

        log.info("GitHub OAuth: email resolved as '{}' for login='{}'", resolvedEmail, login);

        User user = userRepo.findByEmail(resolvedEmail).orElseGet(() -> {
            User u = new User();
            u.setEmail(resolvedEmail);
            u.setName(resolvedName);
            u.setProvider("github");
            u.setGithubId(githubId);
            u.setAvatarUrl(avatarUrl);
            u.setEmailVerified(true);
            u.setCreatedAt(LocalDateTime.now());
            log.info("GitHub OAuth: creating new user '{}'", resolvedEmail);
            return userRepo.save(u);
        });

        // Link GitHub to an existing local (OTP) account that shares the same email
        if (githubId != null && user.getGithubId() == null) {
            user.setGithubId(githubId);
            user.setEmailVerified(true);
            if (avatarUrl != null) user.setAvatarUrl(avatarUrl);
            userRepo.save(user);
            log.info("GitHub OAuth: linked GitHub account to existing user '{}'", resolvedEmail);
        }

        String jwt          = jwtUtil.generateToken(resolvedEmail);
        String ipAddress    = request.getRemoteAddr();
        String userAgent    = request.getHeader("User-Agent");
        String refreshToken = refreshTokenService.generateRefreshToken(
            user, true, ipAddress, userAgent);

        String redirectUrl = frontendUrl + "/oauth-callback.html"
            + "?token="  + URLEncoder.encode(jwt,             StandardCharsets.UTF_8)
            + "&refresh=" + URLEncoder.encode(refreshToken,   StandardCharsets.UTF_8)
            + "&name="    + URLEncoder.encode(user.getName(), StandardCharsets.UTF_8)
            + "&email="   + URLEncoder.encode(resolvedEmail,  StandardCharsets.UTF_8);

        log.info("GitHub OAuth success: user='{}' → {}/oauth-callback.html", resolvedEmail, frontendUrl);
        response.sendRedirect(redirectUrl);
    }

    /**
     * Calls https://api.github.com/user/emails with the OAuth2 Bearer token.
     * Returns the primary+verified email, falling back to any verified email.
     * Returns null only if the API call fails or no verified email exists.
     */
    private String fetchPrimaryEmailFromGitHub(OAuth2AuthenticationToken oauthToken) {
        try {
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(),
                oauthToken.getName()
            );
            if (client == null || client.getAccessToken() == null) {
                log.warn("GitHub OAuth: could not load authorized client for email fetch");
                return null;
            }
            String accessToken = client.getAccessToken().getTokenValue();

            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://api.github.com/user/emails"))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

            HttpResponse<String> resp = HTTP_CLIENT.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() != 200) {
                log.warn("GitHub /user/emails returned HTTP {}", resp.statusCode());
                return null;
            }

            // Response: [{email, primary, verified, visibility}, ...]
            JsonNode nodes = MAPPER.readTree(resp.body());
            String primaryVerified = null;
            String anyVerified     = null;

            for (JsonNode node : nodes) {
                boolean isPrimary  = node.path("primary").asBoolean(false);
                boolean isVerified = node.path("verified").asBoolean(false);
                String  addr       = node.path("email").asText(null);
                if (addr == null || addr.isBlank()) continue;

                if (isPrimary && isVerified) {
                    primaryVerified = addr;
                    break;
                }
                if (isVerified && anyVerified == null) {
                    anyVerified = addr;
                }
            }

            String result = primaryVerified != null ? primaryVerified : anyVerified;
            if (result != null) {
                log.info("GitHub OAuth: /user/emails resolved email '{}'", result);
            } else {
                log.warn("GitHub OAuth: /user/emails contained no verified email");
            }
            return result;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("GitHub OAuth: /user/emails request interrupted");
            return null;
        } catch (Exception e) {
            log.error("GitHub OAuth: error fetching /user/emails — {}", e.getMessage());
            return null;
        }
    }
}
