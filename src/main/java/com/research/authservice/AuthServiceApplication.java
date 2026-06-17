package com.research.authservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.net.URI;

@SpringBootApplication
public class AuthServiceApplication {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceApplication.class);

    public static void main(String[] args) {
        parseAndApplyDatasourceUrl();
        SpringApplication.run(AuthServiceApplication.class, args);
    }

    /**
     * Render (and other PaaS providers) expose PostgreSQL connection strings as:
     *   postgres://username:password@host:5432/database
     *
     * The PostgreSQL JDBC driver requires a credential-free URL:
     *   jdbc:postgresql://host:5432/database
     *
     * with username and password supplied as separate DataSource properties.
     * Embedding credentials in the authority component of the JDBC URL causes
     * the driver's acceptsURL() to return false, which HikariCP surfaces as
     * "Driver claims to not accept jdbcUrl".
     *
     * System.setProperty() entries take precedence over both environment
     * variables and application.properties in Spring's property source order,
     * so values written here are guaranteed to reach HikariCP unchanged.
     */
    private static void parseAndApplyDatasourceUrl() {
        String rawUrl = System.getenv("SPRING_DATASOURCE_URL");

        // Nothing to do: not set (local dev) or already in JDBC form.
        if (rawUrl == null || rawUrl.startsWith("jdbc:")) {
            return;
        }

        try {
            URI uri = new URI(rawUrl);

            // ── Extract components ────────────────────────────────────────────
            String host    = uri.getHost();
            int    port    = uri.getPort() > 0 ? uri.getPort() : 5432;
            String rawPath = uri.getPath();                         // "/database"
            String dbName  = (rawPath != null && rawPath.length() > 1)
                             ? rawPath.substring(1)                 // strip leading "/"
                             : "";
            String query   = uri.getQuery();                        // e.g. "sslmode=require"

            // ── Validate ─────────────────────────────────────────────────────
            if (host == null || host.isBlank()) {
                throw new IllegalStateException(
                    "SPRING_DATASOURCE_URL contains no host. Raw value: " + rawUrl);
            }
            if (dbName.isBlank()) {
                throw new IllegalStateException(
                    "SPRING_DATASOURCE_URL contains no database name. Raw value: " + rawUrl);
            }

            // ── Build credential-free JDBC URL ────────────────────────────────
            // Format: jdbc:postgresql://HOST:PORT/DATABASE[?query]
            // Credentials must NOT appear in the URL authority — they go into
            // spring.datasource.username / spring.datasource.password instead.
            String jdbcUrl = "jdbc:postgresql://" + host + ":" + port + "/" + dbName
                           + (query != null ? "?" + query : "");

            if (!jdbcUrl.startsWith("jdbc:postgresql:")) {
                throw new IllegalStateException("Constructed JDBC URL is invalid: " + jdbcUrl);
            }

            System.setProperty("spring.datasource.url", jdbcUrl);

            // ── Extract credentials from URL userInfo ─────────────────────────
            // Render embeds username:password in the authority section.
            // Only set system properties if the corresponding env var is absent,
            // so explicit SPRING_DATASOURCE_USERNAME/PASSWORD vars still win.
            String userInfo = uri.getUserInfo();  // "username:password" or null
            if (userInfo != null && !userInfo.isBlank()) {
                String[] parts    = userInfo.split(":", 2);
                String   username = parts[0];
                String   password = parts.length > 1 ? parts[1] : "";

                if (System.getenv("SPRING_DATASOURCE_USERNAME") == null
                        && !username.isBlank()) {
                    System.setProperty("spring.datasource.username", username);
                }
                if (System.getenv("SPRING_DATASOURCE_PASSWORD") == null
                        && !password.isBlank()) {
                    System.setProperty("spring.datasource.password", password);
                }
            }

            // ── Startup log — credentials are never logged ────────────────────
            log.info("=== DataSource URL parsed ===");
            log.info("  Host     : {}:{}", host, port);
            log.info("  Database : {}", dbName);
            log.info("  JDBC URL : {}", jdbcUrl);
            log.info("============================");

        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(
                "Failed to parse SPRING_DATASOURCE_URL as a postgres:// URI. " +
                "Ensure Render's 'Internal Database URL' is used: " + e.getMessage(), e);
        }
    }
}
