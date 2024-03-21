package com.study.library.security.handler;

import com.study.library.entity.User;
import com.study.library.repository.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    @Value("${client.deploy-address}")
    private String clientAddress;

    @Autowired
    private UserMapper userMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // class org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
        System.out.println(authentication.getClass());
        // class org.springframework.security.oauth2.core.user.DefaultOAuth2User
        System.out.println(authentication.getPrincipal().getClass());
        // Name: [111206998232404225570], Granted Authorities: 
        // [[ROLE_USER, SCOPE_https://www.googleapis.com/auth/userinfo.email, SCOPE_https://www.googleapis.com/auth/userinfo.profile, SCOPE_openid]], User Attributes: [{id=111206998232404225570, provider=Google}]
        System.out.println(authentication.getPrincipal());
        // 111206998232404225570
        System.out.println(authentication.getName());

        String name = authentication.getName(); // sub
        User user = userMapper.findUserByOAuth2name(name);
        // Oauth2 로그인을 통해 회원 가입이 되어있지 않는 상태
        // Oauth2 동기화
        if(user == null) {
            DefaultOAuth2User oAuth2User = (DefaultOAuth2User) authentication.getPrincipal(); // Authentication에서 다운캐스팅
            String providerName =  oAuth2User.getAttribute("provider").toString();

            response.sendRedirect("http://" + clientAddress + "/auth/oauth2?name=" + name + "&provider=" + providerName);
            return;
        }


        // Oauth2 로그인을 통해 회원가입을 진행한 기록이 있는지 상태

    }
}
