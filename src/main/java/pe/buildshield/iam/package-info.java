/**
 * Microservicio Identidad y Acceso (contexto genérico): registro de organizaciones, sesiones JWT,
 * recuperación de contraseña y usuarios con su rol. Publica en {@code buildshield.iam} y consume
 * {@code buildshield.subscription}.
 *
 * <p>Capas: {@code interfaces} (REST) → {@code application} (casos de uso) → {@code domain} (Java puro);
 * {@code infrastructure} implementa los puertos (JPA, JDBC, Kafka, correo). {@code shared} es el kernel
 * compartido copiado del Core.
 */
package pe.buildshield.iam;
