package cl.duoc.vidasalud.bff.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Set;

public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final String PREFIJO_URI = "api://";

    private final String expectedAudience;
    private final Set<String> audienciasAceptadas;

    public AudienceValidator(String expectedAudience) {
        this.expectedAudience = expectedAudience;
        String clientId = expectedAudience.startsWith(PREFIJO_URI)
                ? expectedAudience.substring(PREFIJO_URI.length())
                : expectedAudience;
        this.audienciasAceptadas = Set.of(PREFIJO_URI + clientId, clientId);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiencias = jwt.getAudience();
        if (audiencias != null && audiencias.stream().anyMatch(audienciasAceptadas::contains)) {
            return OAuth2TokenValidatorResult.success();
        }
        OAuth2Error error = new OAuth2Error(
                "invalid_token",
                "El token no tiene la audience esperada (" + expectedAudience + ")",
                null);
        return OAuth2TokenValidatorResult.failure(error);
    }
}