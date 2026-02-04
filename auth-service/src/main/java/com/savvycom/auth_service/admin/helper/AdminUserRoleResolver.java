package com.savvycom.auth_service.admin.helper;

import com.savvy.common.exception.BusinessException;
import com.savvy.common.exception.ErrorCode;
import com.savvycom.auth_service.entity.Role;
import com.savvycom.auth_service.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class AdminUserRoleResolver {

    private static final String DEFAULT_ROLE_STUDENT = "ROLE_STUDENT";

    private final RoleRepository roleRepository;

    public Set<Role> resolveRolesOrDefault(List<String> roleNames) {
        List<String> names = (roleNames == null || roleNames.isEmpty())
                ? List.of(DEFAULT_ROLE_STUDENT) : roleNames;

        Set<Role> roles = new HashSet<>();
        for (String rn : names) {
            if (!StringUtils.hasText(rn)) continue;

            String raw = rn.trim().toUpperCase(Locale.ROOT);
            String normalized = raw.startsWith("ROLE_") ? raw : "ROLE_" + raw;

            Role r = roleRepository.findByName(normalized)
                    .orElseGet(() -> roleRepository.findByName(raw)
                            .orElseThrow(() -> new BusinessException(
                                    ErrorCode.RESOURCE_NOT_FOUND,
                                    "Role not found: " + normalized
                            )));

            roles.add(r);
        }
        return roles;
    }
}
