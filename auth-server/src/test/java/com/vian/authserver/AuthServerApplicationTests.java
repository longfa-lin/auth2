package com.example.authserver;

import com.vian.authserver.AuthServerApplication;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.UserDetailsManager;

import java.time.Duration;
import java.util.UUID;

@SpringBootTest(classes = AuthServerApplication.class)
class AuthServerApplicationTests {

    @Test
    void contextLoads() {
    }

    @Resource
    private UserDetailsManager userDetailsManager;

    /**
     * 创建用户信息
     */
//    TODO
    @Test
    void testSaveUser() {
        UserDetails userDetails = User.builder().passwordEncoder(s -> "{bcrypt}" + new BCryptPasswordEncoder().encode(s))
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        userDetailsManager.createUser(userDetails);
    }

    @Resource
    private RegisteredClientRepository registeredClientRepository;

    @Test
    void testSaveClient() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret("{bcrypt}" + new BCryptPasswordEncoder().encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .redirectUri("http://auth-server:8080/authorized")
                .redirectUri("http://client:8082/login/oauth2/code/demo")
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofHours(1))
                        .build())
                .build();
        registeredClientRepository.save(registeredClient);
    }

}
