package com.research.authservice;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Redirects the browser to the frontend error page when GitHub OAuth fails
 * (e.g. user denies access, invalid state, revoked token).
 * Uses FRONTEND_URL so the redirect always goes to the correct domain in
 * every environment.
 */
@Component
public class OAuthFailureHandler implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthFailureHandler.class);

    @Value("${app.frontend-url:http://localhost:3001}")
    private String frontendUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        log.warn("GitHub OAuth authentication failure: {}", exception.getMessage());
        String redirectUrl = frontendUrl + "/login.html?error=oauth_failed";
        log.info("GitHub OAuth → failure redirect: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }
}
