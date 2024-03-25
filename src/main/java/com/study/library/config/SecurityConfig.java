package com.study.library.config;

import com.study.library.security.exception.AuthEntryPoint;
import com.study.library.security.filter.JwtAuthenticationFilter;
import com.study.library.security.filter.PermitAllFilter;
import com.study.library.security.handler.OAuth2SuccessHandler;
import com.study.library.service.Oauth2PrincipalUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PermitAllFilter permitAllFilter;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    @Autowired
    private AuthEntryPoint authEntryPoint;
    @Autowired
    private Oauth2PrincipalUserService oauth2PrincipalUserService;
    @Autowired
    private OAuth2SuccessHandler oAuth2SuccessHandler;

    @Bean
        public BCryptPasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.cors();
            http.csrf().disable();
            http.authorizeRequests()
                    .antMatchers("/server/**", "/auth/**") // 3
                    .permitAll()
                    .antMatchers("/mail/authenticate")
                    .permitAll()
                    .antMatchers("/admin/**")
                    .hasRole("ADMIN")
                    .anyRequest()
                    .authenticated()
                    .and()
                    .addFilterAfter(permitAllFilter, LogoutFilter.class) //(LogoutFilter 후 필터추가) // 1
                    .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)  //(Username 전에 필터추가) // 2
                    .exceptionHandling()
                    .authenticationEntryPoint(authEntryPoint) // EntryPoint 경로지정
                    .and()
                    .oauth2Login()
                    .successHandler(oAuth2SuccessHandler)
                    .userInfoEndpoint()
                    // OAuth2 로그인 토큰 검사
                    .userService(oauth2PrincipalUserService);
    }
}
