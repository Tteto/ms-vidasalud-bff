package cl.duoc.vidasalud.bff.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

        @Value("${azure.ad.audience}")
        private String expectedAudience;

        private final AzureRolesConverter azureRolesConverter;

        public SecurityConfig(AzureRolesConverter azureRolesConverter) {
                this.azureRolesConverter = azureRolesConverter;
        }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
                http
                                .cors(Customizer.withDefaults())
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/actuator/health").permitAll()
                                                .requestMatchers("/api/report/**").hasRole("ADMIN")
                                                .requestMatchers("/api/catalog/**").hasRole("ADMIN")
                                                .anyRequest().authenticated())
                                .oauth2ResourceServer(oauth2 -> oauth2
                                                .jwt(jwt -> jwt
                                                                .decoder(jwtDecoder)
                                                                .jwtAuthenticationConverter(azureRolesConverter))

                                                .authenticationEntryPoint(
                                                                (request, response, ex) -> writeError(response,
                                                                                HttpServletResponse.SC_UNAUTHORIZED,
                                                                                "Token ausente o inválido: "
                                                                                                + ex.getMessage()))

                                                .accessDeniedHandler(
                                                                (request, response, ex) -> writeError(response,
                                                                                HttpServletResponse.SC_FORBIDDEN,
                                                                                "No tienes el rol requerido para este recurso.")));

                return http.build();
        }

        @Bean
        public JwtDecoder jwtDecoder(
                        @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
                NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();

                OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> withIssuer = JwtValidators
                                .createDefaultWithIssuer(issuerUri);
                OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> audienceValidator = new AudienceValidator(
                                expectedAudience);
                OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> combined = new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                                withIssuer, audienceValidator);

                decoder.setJwtValidator(combined);
                return decoder;
        }

        private void writeError(HttpServletResponse response, int status, String mensaje) throws java.io.IOException {
                response.setStatus(status);
                response.setContentType("application/json");
                Map<String, Object> body = new HashMap<>();
                body.put("timestamp", Instant.now().toString());
                body.put("status", status);
                body.put("error", mensaje);
                new ObjectMapper().writeValue(response.getWriter(), body);
        }
}