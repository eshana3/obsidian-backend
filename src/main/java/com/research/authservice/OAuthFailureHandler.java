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

        // Use oauth-callback.html with error param so the same page handles
        // both success and failure — avoids any login.html routing issues
        String base = frontendUrl.endsWith("/")
            ? frontendUrl.substring(0, frontendUrl.length() - 1)
            : frontendUrl;
        String redirectUrl = base + "/oauth-callback.html?error=oauth_failed";
        log.info("GitHub OAuth failure → {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }
}
