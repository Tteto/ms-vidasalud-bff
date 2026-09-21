package cl.duoc.vidasalud.bff.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/report")
@PreAuthorize("hasRole('ADMIN')")
public class ReportProxyController {

    private final RestTemplate restTemplate;
    private final String reportUrl;

    public ReportProxyController(
            RestTemplate restTemplate,
            @Value("${microservicios.report-url}") String reportUrl) {
        this.restTemplate = restTemplate;
        this.reportUrl = reportUrl;
    }

    @GetMapping("/kpis")
    public ResponseEntity<String> kpis(@RequestParam(defaultValue = "last24h") String range) {
        String url = reportUrl + "/api/report/kpis?range=" + range;
        return restTemplate.exchange(url, HttpMethod.GET, HttpEntity.EMPTY, String.class);
    }

    @GetMapping("/top-services")
    public ResponseEntity<String> topServicios(@RequestParam(defaultValue = "last7d") String range) {
        String url = reportUrl + "/api/report/top-services?range=" + range;
        return restTemplate.exchange(url, HttpMethod.GET, HttpEntity.EMPTY, String.class);
    }
}
