package cl.duoc.vidasalud.bff;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas básicas exigidas por el encargo. No prueban lógica de
 * negocio (no hay: el BFF es un proxy), sino el contrato de
 * seguridad, que es justo lo que pondera el indicador de 40%.
 *
 * Se mockea JwtDecoder para no depender de una llamada real al
 * tenant de Azure durante el test.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "azure.ad.audience=api://test-audience",
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://login.microsoftonline.com/test-tenant/v2.0",
        // Puerto sin nada escuchando: el test no depende de que haya
        // (o no) un microservicio corriendo en la máquina.
        "microservicios.report-url=http://localhost:1"
})
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtDecoder jwtDecoder;

    @Test
    void sinTokenDebeRetornar401() throws Exception {
        mockMvc.perform(get("/api/appointments"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "PACIENTE")
    void conRolInsuficienteDebeRetornar403() throws Exception {
        mockMvc.perform(get("/api/report/kpis"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void conRolCorrectoNoDebeRetornar401Ni403() throws Exception {
        // La seguridad deja pasar la request; luego el proxy no logra
        // conectar con el microservicio y el BFF responde 503 (Service
        // Unavailable). Que llegue a 503, y no a 401/403, confirma que
        // la capa de seguridad SÍ autorizó al rol ADMIN.
        mockMvc.perform(get("/api/report/kpis"))
                .andExpect(status().isServiceUnavailable());
    }
}