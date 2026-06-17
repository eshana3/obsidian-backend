package com.research.authservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceApplication.class);

    public static void main(String[] args) {
        // Render (and other PaaS providers) expose PostgreSQL URLs as:
        //   postgres://user:pass@host:5432/dbname
        // HikariCP requires the JDBC form:
        //   jdbc:postgresql://user:pass@host:5432/dbname
        // System properties override environment variables in Spring's property
        // resolution order, so setting it here rewrites the value before any
        // datasource autoconfiguration runs.
        String rawUrl = System.getenv("SPRING_DATASOURCE_URL");
        if (rawUrl != null && !rawUrl.startsWith("jdbc:")) {
            String jdbcUrl = "jdbc:postgresql://" + rawUrl.replaceFirst("^postgres(?:ql)?://", "");
            System.setProperty("spring.datasource.url", jdbcUrl);
            log.info("DataSource URL converted to JDBC format (credentials not logged)");
        }

        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
