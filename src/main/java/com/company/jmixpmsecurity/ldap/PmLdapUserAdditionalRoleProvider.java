package com.company.jmixpmsecurity.ldap;

import io.jmix.ldap.userdetails.LdapUserAdditionalRoleProvider;
import io.jmix.security.model.RowLevelRole;
import io.jmix.security.role.RoleGrantedAuthorityUtils;
import io.jmix.security.role.RowLevelRoleRepository;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Component
public class PmLdapUserAdditionalRoleProvider implements LdapUserAdditionalRoleProvider {


    private final RowLevelRoleRepository rowLevelRoleRepository;
    private final RoleGrantedAuthorityUtils roleGrantedAuthorityUtils;

    public PmLdapUserAdditionalRoleProvider(RowLevelRoleRepository rowLevelRoleRepository, RoleGrantedAuthorityUtils roleGrantedAuthorityUtils) {
        this.rowLevelRoleRepository = rowLevelRoleRepository;
        this.roleGrantedAuthorityUtils = roleGrantedAuthorityUtils;
    }

    @Override
    public Set<GrantedAuthority> getAdditionalRoles(DirContextOperations ldapUserCtx, String username) {
        String[] roleCodes = ldapUserCtx.getStringAttributes("employeeType");
        if (roleCodes == null || roleCodes.length == 0) {
            return Collections.emptySet();
        }

        Set<GrantedAuthority> authorities = new HashSet<>();
        for (String roleCode : roleCodes) {
            RowLevelRole role = rowLevelRoleRepository.findRoleByCode(roleCode);
            if (role != null) {
                GrantedAuthority authority = roleGrantedAuthorityUtils.createRowLevelRoleGrantedAuthority(role);
                authorities.add(authority);
            }
        }
        return authorities;
    }
}
