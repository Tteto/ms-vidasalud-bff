package cl.duoc.vidasalud.bff.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/catalog")
@PreAuthorize("hasRole('ADMIN')")
public class CatalogProxyController {

    private final RestTemplate restTemplate;
    private final String catalogUrl;

    public CatalogProxyController(
            RestTemplate restTemplate,
            @Value("${microservicios.catalog-url}") String catalogUrl) {
        this.restTemplate = restTemplate;
        this.catalogUrl = catalogUrl;
    }

    @GetMapping("/services")
    public ResponseEntity<String> listarPrestaciones() {
        return restTemplate.exchange(catalogUrl + "/api/catalog/services", HttpMethod.GET, HttpEntity.EMPTY, String.class);
    }

    @PostMapping("/services")
    public ResponseEntity<String> crearPrestacion(@RequestBody String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return restTemplate.exchange(catalogUrl + "/api/catalog/services", HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    }

    @PutMapping("/services/{id}")
    public ResponseEntity<String> actualizarPrestacion(@PathVariable Long id, @RequestBody String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return restTemplate.exchange(catalogUrl + "/api/catalog/services/" + id, HttpMethod.PUT, new HttpEntity<>(body, headers), String.class);
    }
}
