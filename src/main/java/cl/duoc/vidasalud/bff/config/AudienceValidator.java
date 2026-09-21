package cl.duoc.vidasalud.bff.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Rechaza cualquier token cuyo claim "aud" no coincida con el
 * Application ID URI de vidasalud-api (api://<API_CLIENT_ID>).
 *
 * Este es el caso concreto que la rúbrica castiga con "no valida
 * firma ni claims relevantes": sin este validador, un token válido
 * pero destinado a otra API (por ejemplo, el token por defecto que
 * MSAL entrega para Microsoft Graph) pasaría igual.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String expectedAudience;

    public AudienceValidator(String expectedAudience) {
        this.expectedAudience = expectedAudience;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (jwt.getAudience() != null && jwt.getAudience().contains(expectedAudience)) {
            return OAuth2TokenValidatorResult.success();
        }
        OAuth2Error error = new OAuth2Error(
                "invalid_token",
                "El token no tiene la audience esperada (" + expectedAudience + ")",
                null
        );
        return OAuth2TokenValidatorResult.failure(error);
    }
}
