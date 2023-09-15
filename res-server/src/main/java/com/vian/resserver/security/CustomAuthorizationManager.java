package com.vian.resserver.security;

import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * @Description: TODO
 * @ClassName: CustomAuthorizationManager
 * @Author: lin long fa
 * @Date: 2023-09-15 18:01:14
 * @Version: v0.0.1
 * @Edit: Number Date User Remark
 **/
@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationManager<T> implements AuthorizationManager<T> {
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final HttpServletRequest httpServletRequest;
    private final JdbcTemplate jdbcTemplate;

    @Override
    public AuthorizationDecision check(Supplier<Authentication> supplier, T object) {
        Authentication authentication = supplier.get();
        log.info("authentication: {}", authentication);
        log.info("object: {}", object);
        boolean isAnonymous = authentication != null && !this.trustResolver.isAnonymous(authentication)
                && authentication.isAuthenticated();
        if (!isAnonymous) {
            return new AuthorizationDecision(false);
        }
//        String servletPath = httpServletRequest.getServletPath();
//        log.info("servletPath: {}", servletPath);
        //得到该用户已被授权的角色对象
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities(); //ROLE_USER
        //采用Ant语法规则的匹配器，只因为它用起来简单
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        String requestURI = httpServletRequest.getServletPath();
//        String requestURI = ((FilterInvocation) object).getRequest().getRequestURI(); // /products
        List<Map<String, Object>> dbAuthList = jdbcTemplate.queryForList("select r.role_id,r.role_name,u.url_pattern , u.namespace from role r, role_url_mapping ru , url_resource u where r.role_id = ru.role_id and ru.url_id = u.url_id and u.namespace =?", new Object[]{"res-sample"});
        log.debug("Authority data has been queried:" + dbAuthList);
        //先比较URI，有符合条件的在判断是否有访问权限
        for (Map<String, Object> dbAuthority : dbAuthList) {
            // /user/create     /user/*
            if (antPathMatcher.match(dbAuthority.get("url_pattern").toString(), requestURI)) {
                // /user/* -> USER
                for (GrantedAuthority userRole : roles) {
                    //因为角色名在Spring OAuth2 中固定以ROLE_开头，所以增加上
                    String dbRoleName = "role_" + dbAuthority.get("role_name").toString().toLowerCase();
                    if (dbRoleName.equals(userRole.getAuthority().toLowerCase())) {
                        return new AuthorizationDecision(true);
                    }
                }
            }
        }
        return new AuthorizationDecision(false);
    }
}
