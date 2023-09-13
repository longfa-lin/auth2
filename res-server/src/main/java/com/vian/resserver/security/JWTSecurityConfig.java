package com.vian.resserver.security;

import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class JWTSecurityConfig {

//    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
//    String jwkSetUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//        http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
//            @Override
//            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                response.getWriter().println("{code:403,message:'Access Denied'}");
//            }
//        });
//        http.exceptionHandling(Customizer.withDefaults());
//        http.authorizeRequests((authz) -> authz
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtRoleConverter());
        http.authorizeHttpRequests((auth) -> auth
//                        .requestMatchers("/products").hasAuthority("SCOPE_message.read")
                .requestMatchers("/products").hasRole("USER")
                .requestMatchers("/create").hasAuthority("SCOPE_message.write")
                .anyRequest().authenticated());
        http.authorizeRequests().accessDecisionManager(accessDecisionManager()).anyRequest().authenticated();
        http.oauth2ResourceServer(
                (oauth2) ->
                        oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
        );
        return http.build();
    }

    /*@Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
    }*/

    @Resource
    RoleBasedVoter roleBasedVoter;

    @Bean
    //实例化决策器对象
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters
                = Arrays.asList(
                new WebExpressionVoter(),
                roleBasedVoter,
                new AuthenticatedVoter());
        return new UnanimousBased(decisionVoters);
    }
}