package com.chessgrinder.chessgrinder.security;

import com.chessgrinder.chessgrinder.entities.UserEntity;
import com.chessgrinder.chessgrinder.repositories.UserRepository;
import com.chessgrinder.chessgrinder.service.RoleService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleService roleService;

    @Mock
    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;

    @Mock
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

    private LoginService loginService;

    @BeforeEach
    void setUp() {
        loginService = new LoginService(userRepository, roleService, oidcUserService, oauth2UserService, "");
    }

    @Test
    void loadOauth2User_shouldUsePreferredUsernameAsFallbackNameForNewChessComUsers() {
        OAuth2UserRequest request = oauth2Request("chesscom");
        OAuth2User principal = new DefaultOAuth2User(List.of(), Map.of(
                "email", "player@example.com",
                "preferred_username", "PlayerHandle"
        ), "email");

        when(oauth2UserService.loadUser(request)).thenReturn(principal);
        when(userRepository.findByUsername("player@example.com")).thenReturn(null);
        when(userRepository.findByUsertag("PlayerHandle")).thenReturn(null);
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> {
            UserEntity user = invocation.getArgument(0);
            if (user.getId() == null) {
                user.setId(UUID.randomUUID());
            }
            return user;
        });

        loginService.loadOauth2User(request);

        ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository, times(2)).save(userCaptor.capture());

        List<UserEntity> savedUsers = userCaptor.getAllValues();
        assertThat(savedUsers.get(0).getName()).isEqualTo("PlayerHandle");
        assertThat(savedUsers.get(0).getUsertag()).isEqualTo("PlayerHandle");
        assertThat(savedUsers.get(0).getProvider()).isEqualTo(UserEntity.Provider.CHESSCOM);
        assertThat(savedUsers.get(1).getChesscomUsername()).isEqualTo("PlayerHandle");
    }

    @Test
    void loginOrRegister_shouldBackfillBlankNameFromPreferredUsertag() {
        UserEntity existingUser = UserEntity.builder()
                .id(UUID.randomUUID())
                .username("player@example.com")
                .provider(UserEntity.Provider.CHESSCOM)
                .build();

        when(userRepository.findByUsername(existingUser.getUsername())).thenReturn(existingUser);
        when(userRepository.findByUsertag("PlayerHandle")).thenReturn(null);
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserEntity result = loginService.loginOrRegister(
                existingUser.getUsername(),
                "PlayerHandle",
                null,
                null,
                UserEntity.Provider.CHESSCOM
        );

        assertThat(result.getName()).isEqualTo("PlayerHandle");
        assertThat(result.getUsertag()).isEqualTo("PlayerHandle");
        assertThat(result.getChesscomUsername()).isEqualTo("PlayerHandle");
        verify(userRepository, times(3)).save(existingUser);
    }

    @Test
    void loginOrRegister_shouldIgnoreTakenUsertagForNewUserWithoutThrowing() {
        UserEntity anotherUser = UserEntity.builder()
                .id(UUID.randomUUID())
                .usertag("TakenTag")
                .build();

        when(userRepository.findByUsername("player@example.com")).thenReturn(null);
        when(userRepository.findByUsertag("TakenTag")).thenReturn(anotherUser);
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> {
            UserEntity user = invocation.getArgument(0);
            if (user.getId() == null) {
                user.setId(UUID.randomUUID());
            }
            return user;
        });

        UserEntity result = loginService.loginOrRegister(
                "player@example.com",
                "TakenTag",
                null,
                null,
                UserEntity.Provider.CHESSCOM
        );

        assertThat(result.getUsertag()).isNull();
        assertThat(result.getName()).isNull();
        assertThat(result.getChesscomUsername()).isNull();
        verify(userRepository, times(1)).save(any(UserEntity.class));
    }

    @Test
    void loadOidcUser_shouldFallbackToUsernameWhenNameMissing() {
        OidcUserRequest request = oidcRequest("chesscom");
        OidcUser principal = new DefaultOidcUser(
                List.of(),
                new OidcIdToken(
                        "token",
                        Instant.now(),
                        Instant.now().plusSeconds(60),
                        Map.of(
                                IdTokenClaimNames.SUB, "sub-1",
                                "email", "player@example.com",
                                "preferred_username", "PlayerHandle"
                        )
                )
        );

        when(oidcUserService.loadUser(request)).thenReturn(principal);
        when(userRepository.findByUsername("player@example.com")).thenReturn(null);
        when(userRepository.findByUsertag("PlayerHandle")).thenReturn(null);
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> {
            UserEntity user = invocation.getArgument(0);
            if (user.getId() == null) {
                user.setId(UUID.randomUUID());
            }
            return user;
        });

        loginService.loadOidcUser(request);

        ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository, times(2)).save(userCaptor.capture());
        assertThat(userCaptor.getAllValues().get(0).getName()).isEqualTo("PlayerHandle");
    }

    @Test
    void loginOrRegister_shouldNotOverwriteExistingName() {
        UserEntity existingUser = UserEntity.builder()
                .id(UUID.randomUUID())
                .username("player@example.com")
                .name("Existing Name")
                .usertag("PlayerHandle")
                .provider(UserEntity.Provider.CHESSCOM)
                .chesscomUsername("PlayerHandle")
                .build();

        when(userRepository.findByUsername(existingUser.getUsername())).thenReturn(existingUser);
        when(userRepository.findByUsertag("PlayerHandle")).thenReturn(null);

        UserEntity result = loginService.loginOrRegister(
                existingUser.getUsername(),
                "PlayerHandle",
                "New Name",
                null,
                UserEntity.Provider.CHESSCOM
        );

        assertThat(result.getName()).isEqualTo("Existing Name");
        verify(userRepository, never()).save(argThat(user -> "New Name".equals(user.getName())));
    }

    private OAuth2UserRequest oauth2Request(String registrationId) {
        ClientRegistration registration = clientRegistration(registrationId);
        return new OAuth2UserRequest(registration, accessToken());
    }

    private OidcUserRequest oidcRequest(String registrationId) {
        ClientRegistration registration = clientRegistration(registrationId);
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(60), Map.of(IdTokenClaimNames.SUB, "sub-1"));
        return new OidcUserRequest(registration, accessToken(), idToken);
    }

    private ClientRegistration clientRegistration(String registrationId) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId("client-id")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://example.com/authorize")
                .tokenUri("https://example.com/token")
                .jwkSetUri("https://example.com/jwks")
                .issuerUri("https://example.com")
                .userNameAttributeName("sub")
                .scope("openid", "profile", "email")
                .build();
    }

    private OAuth2AccessToken accessToken() {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                Instant.now(),
                Instant.now().plusSeconds(60)
        );
    }
}
