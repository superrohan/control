package com.controllerapp.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.controllerapp.audit.ServiceAuditService;

@RestController
@RequestMapping("/controller/internal/rh")
public class RequestHistoryInternalController {

    private final ServiceAuditService auditService;

    public RequestHistoryInternalController(ServiceAuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/requests/{requestId}")
    @PreAuthorize("hasRole('RHAPP_SERVICE')")
    public ResponseEntity<Map<String, Object>> getRequestDetails(
            @PathVariable String requestId,
            @AuthenticationPrincipal Jwt jwt) {

        String callingService = auditService.extractCallingService(jwt);
        auditService.audit(callingService, "/controller/internal/rh/requests/" + requestId,
                "GET_REQUEST_DETAILS", requestId);

        return ResponseEntity.ok(Map.of(
                "requestId", requestId,
                "status", "completed",
                "retrievedFor", callingService
        ));
    }

    @PostMapping("/requests/{requestId}/replay")
    @PreAuthorize("hasRole('RHAPP_SERVICE')")
    public ResponseEntity<Map<String, Object>> replayRequest(
            @PathVariable String requestId,
            @AuthenticationPrincipal Jwt jwt) {

        String callingService = auditService.extractCallingService(jwt);
        auditService.audit(callingService, "/controller/internal/rh/requests/" + requestId + "/replay",
                "REPLAY_REQUEST", requestId);

        return ResponseEntity.ok(Map.of(
                "requestId", requestId,
                "status", "replayed",
                "replayedFor", callingService
        ));
    }
}
