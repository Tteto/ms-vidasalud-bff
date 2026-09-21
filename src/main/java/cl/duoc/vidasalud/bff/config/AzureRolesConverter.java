package cl.duoc.vidasalud.bff.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Azure AD entrega los App Roles asignados al usuario en el claim
 * "roles" del access token (ej: ["Admin"] o ["Recepcionista"]).
 *
 * Spring Security, por defecto, solo sabe leer el claim estándar
 * "scope"/"scp". Si no se registra este converter, hasRole("ADMIN") y
 * @PreAuthorize siempre van a fallar aunque el token traiga el rol
 * correcto — es el error más común en este punto de la rúbrica.
 *
 * También se mantienen los scopes (para endpoints protegidos por scope
 * en vez de por rol), con el prefijo SCOPE_ que usa Spring por defecto.
 */
@Component
public class AzureRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> scopeAuthorities = scopesConverter.convert(jwt);

        List<String> roles = jwt.getClaimAsStringList("roles");
        Stream<GrantedAuthority> roleAuthorities = (roles == null ? List.<String>of() : roles)
                .stream()
                .map(rol -> new SimpleGrantedAuthority("ROLE_" + rol.toUpperCase()));

        Collection<GrantedAuthority> authorities = Stream
                .concat(scopeAuthorities == null ? Stream.empty() : scopeAuthorities.stream(), roleAuthorities)
                .collect(Collectors.toSet());

        JwtAuthenticationConverter delegate = new JwtAuthenticationConverter();
        delegate.setJwtGrantedAuthoritiesConverter(source -> authorities);
        return delegate.convert(jwt);
    }
}
