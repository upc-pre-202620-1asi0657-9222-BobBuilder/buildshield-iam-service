package pe.buildshield.iam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** Identidad y Acceso de BuildShield (microservicio, puerto 8081, base iam_db). */
@SpringBootApplication
@ConfigurationPropertiesScan
public class BuildshieldIamApplication {

    public static void main(String[] args) {
        SpringApplication.run(BuildshieldIamApplication.class, args);
    }
}
