package com.controllerapp.security;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Converts the 'roles' claim from a Microsoft Entra ID JWT into Spring Security
 * granted authorities with the ROLE_ prefix.
 *
 * Mapping:
 *   ADMINAPP_SERVICE  → ROLE_ADMINAPP_SERVICE
 *   RHAPP_SERVICE     → ROLE_RHAPP_SERVICE
 *
 * Tokens without a 'roles' claim yield an empty authority set, which will cause
 * authorization to fail at the SecurityConfig level — enforcing service-only access.
 */
public class JwtRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Object rolesClaim = jwt.getClaim(ROLES_CLAIM);

        if (rolesClaim == null) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) rolesClaim;

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                .collect(Collectors.toUnmodifiableList());
    }
}
