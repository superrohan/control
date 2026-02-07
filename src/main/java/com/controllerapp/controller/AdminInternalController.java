package com.controllerapp.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.controllerapp.audit.ServiceAuditService;

@RestController
@RequestMapping("/controller/internal/admin")
public class AdminInternalController {

    private final ServiceAuditService auditService;

    public AdminInternalController(ServiceAuditService auditService) {
        this.auditService = auditService;
    }

    @PostMapping("/force-close/{scanId}")
    @PreAuthorize("hasRole('ADMINAPP_SERVICE')")
    public ResponseEntity<Map<String, Object>> forceCloseScan(
            @PathVariable String scanId,
            @AuthenticationPrincipal Jwt jwt) {

        String callingService = auditService.extractCallingService(jwt);
        auditService.audit(callingService, "/controller/internal/admin/force-close/" + scanId,
                "FORCE_CLOSE_SCAN", scanId);

        return ResponseEntity.ok(Map.of(
                "status", "closed",
                "scanId", scanId,
                "closedBy", callingService
        ));
    }

    @PostMapping("/suspend-user/{userId}")
    @PreAuthorize("hasRole('ADMINAPP_SERVICE')")
    public ResponseEntity<Map<String, Object>> suspendUser(
            @PathVariable String userId,
            @AuthenticationPrincipal Jwt jwt) {

        String callingService = auditService.extractCallingService(jwt);
        auditService.audit(callingService, "/controller/internal/admin/suspend-user/" + userId,
                "SUSPEND_USER", userId);

        return ResponseEntity.ok(Map.of(
                "status", "suspended",
                "userId", userId,
                "suspendedBy", callingService
        ));
    }
}
