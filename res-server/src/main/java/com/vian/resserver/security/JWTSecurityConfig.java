package com.vian.resserver.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

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
        http.authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/products").hasAuthority("SCOPE_message.read")
                        .requestMatchers("/create").hasAuthority("SCOPE_message.write")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(
                        (oauth2) ->
                                oauth2.jwt(Customizer.withDefaults())
                );
        return http.build();
    }

    /*@Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
    }*/
}