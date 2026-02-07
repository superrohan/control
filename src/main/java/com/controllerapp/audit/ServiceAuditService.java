package com.controllerapp.audit;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

/**
 * Centralised service-level audit logger.
 * Extracts calling service identity from JWT claims (appid or azp)
 * and emits structured audit log lines for every inter-service operation.
 */
@Service
public class ServiceAuditService {

    private static final Logger log = LoggerFactory.getLogger(ServiceAuditService.class);

    private static final String APPID_CLAIM = "appid";
    private static final String AZP_CLAIM = "azp";

    /**
     * Extracts the calling service identifier from the JWT.
     * Prefers 'appid' (v1 tokens) and falls back to 'azp' (v2 tokens).
     */
    public String extractCallingService(Jwt jwt) {
        String appId = jwt.getClaimAsString(APPID_CLAIM);
        if (appId != null && !appId.isBlank()) {
            return appId;
        }

        String azp = jwt.getClaimAsString(AZP_CLAIM);
        if (azp != null && !azp.isBlank()) {
            return azp;
        }

        return "unknown-service";
    }

    /**
     * Records a structured audit event and writes it to the log.
     */
    public void audit(String callingService, String endpoint, String action, String resourceId) {
        String correlationId = MDC.get(CorrelationFilter.CORRELATION_ID_KEY);

        ServiceAuditEvent event = new ServiceAuditEvent(
                callingService,
                endpoint,
                action,
                resourceId,
                Instant.now(),
                correlationId
        );

        log.info("SERVICE_AUDIT {\"service\":\"{}\",\"action\":\"{}\",\"resourceId\":\"{}\","
                        + "\"endpoint\":\"{}\",\"correlationId\":\"{}\",\"timestamp\":\"{}\"}",
                event.callingService(),
                event.action(),
                event.resourceId(),
                event.endpoint(),
                event.correlationId(),
                event.timestamp());
    }
}
