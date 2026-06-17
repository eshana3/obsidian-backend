package com.research.authservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.net.URI;

/**
 * Logs datasource connection details at startup.
 * Never logs username or password.
 */
@Component
public class DataSourceLogger {

    private static final Logger log = LoggerFactory.getLogger(DataSourceLogger.class);

    @Value("${spring.datasource.url:not-configured}")
    private String datasourceUrl;

    @Value("${spring.datasource.driver-class-name:org.postgresql.Driver}")
    private String driverClassName;

    @EventListener(ApplicationReadyEvent.class)
    public void logDatasourceInfo() {
        try {
            // Strip "jdbc:" so java.net.URI can parse the remainder.
            // At this point datasourceUrl is already the credential-free form
            // set by AuthServiceApplication.parseAndApplyDatasourceUrl().
            URI uri = new URI(datasourceUrl.replace("jdbc:", ""));

            String host   = uri.getHost() != null ? uri.getHost() : "unknown";
            int    port   = uri.getPort() > 0     ? uri.getPort()  : 5432;
            String dbName = uri.getPath() != null
                    ? uri.getPath().replaceFirst("^/", "")
                    : "unknown";

            // Sanity-check: credentials must not appear in the URL at this point.
            if (uri.getUserInfo() != null) {
                log.warn("DataSource URL unexpectedly contains embedded credentials — " +
                         "check AuthServiceApplication.parseAndApplyDatasourceUrl()");
            }

            log.info("=== DataSource connected ===");
            log.info("  JDBC URL : {}", datasourceUrl);
            log.info("  Host     : {}:{}", host, port);
            log.info("  Database : {}", dbName);
            log.info("  Driver   : {}", driverClassName);
            log.info("===========================");
        } catch (Exception e) {
            log.warn("Could not parse datasource URL for diagnostics: {}", e.getMessage());
        }
    }
}
