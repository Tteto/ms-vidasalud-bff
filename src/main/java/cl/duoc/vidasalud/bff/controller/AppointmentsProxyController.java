package cl.duoc.vidasalud.bff.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

/**
 * Este controller no contiene lógica de negocio: solo reenvía al
 * microservicio de dominio ms-vidasalud-appointments. Cuando la
 * request llega aquí, Spring Security YA validó firma, issuer,
 * audience y vigencia del JWT (ver SecurityConfig), así que si el
 * método se ejecuta es porque el usuario está autenticado.
 *
 * @PreAuthorize agrega una segunda capa de autorización a nivel de
 * método, redundante a propósito con el authorizeHttpRequests() de
 * SecurityConfig para los endpoints de catálogo/reportería; aquí se
 * usa donde el permiso depende también del propio recurso (ver
 * cambiarEstado).
 */
@RestController
@RequestMapping("/api/appointments")
public class AppointmentsProxyController {

    private final RestTemplate restTemplate;
    private final String appointmentsUrl;

    public AppointmentsProxyController(
            RestTemplate restTemplate,
            @Value("${microservicios.appointments-url}") String appointmentsUrl) {
        this.restTemplate = restTemplate;
        this.appointmentsUrl = appointmentsUrl;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','RECEPCIONISTA','PACIENTE')")
    public ResponseEntity<String> listar(@RequestParam(required = false) String status) {
        String url = appointmentsUrl + "/api/appointments" + (status != null ? "?status=" + status : "");
        return restTemplate.exchange(url, HttpMethod.GET, HttpEntity.EMPTY, String.class);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','RECEPCIONISTA','PACIENTE')")
    public ResponseEntity<String> obtener(@PathVariable Long id) {
        String url = appointmentsUrl + "/api/appointments/" + id;
        return restTemplate.exchange(url, HttpMethod.GET, HttpEntity.EMPTY, String.class);
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN','RECEPCIONISTA','PACIENTE')")
    public ResponseEntity<String> crear(@RequestBody String body) {
        String url = appointmentsUrl + "/api/appointments";
        HttpEntity<String> request = jsonEntity(body);
        return restTemplate.exchange(url, HttpMethod.POST, request, String.class);
    }

    /**
     * Cambiar de estado es la operación más sensible del dominio: solo
     * Admin y Recepcionista pueden confirmar/llamar a box/cerrar. Un
     * Paciente puede listar y crear, pero no mover el estado.
     */
    @PutMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN','RECEPCIONISTA')")
    public ResponseEntity<String> cambiarEstado(@PathVariable Long id, @RequestBody String body) {
        String url = appointmentsUrl + "/api/appointments/" + id + "/status";
        HttpEntity<String> request = jsonEntity(body);
        return restTemplate.exchange(url, HttpMethod.PUT, request, String.class);
    }

    private HttpEntity<String> jsonEntity(String body) {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        return new HttpEntity<>(body, headers);
    }
}
