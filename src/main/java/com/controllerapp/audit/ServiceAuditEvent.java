package com.controllerapp.audit;

import java.time.Instant;

/**
 * Immutable record representing a service-level audit event.
 * Captures the calling service identity, the action performed,
 * the target resource, and correlation metadata.
 */
public record ServiceAuditEvent(
        String callingService,
        String endpoint,
        String action,
        String resourceId,
        Instant timestamp,
        String correlationId
) {
    public ServiceAuditEvent {
        if (callingService == null || callingService.isBlank()) {
            throw new IllegalArgumentException("callingService must not be blank");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action must not be blank");
        }
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
