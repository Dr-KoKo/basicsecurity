package io.security.basicsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}123123").roles("USER")
                .and().withUser("sys").password("{noop}123123").roles("SYS", "USER")
                .and().withUser("admin").password("{noop}123123").roles("ADMIN", "SYS", "USER");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf((csrf) ->
                        csrf
                                .ignoringRequestMatchers("/kakao/**", "/naver/**", "/google/**")
                )
                .authorizeHttpRequests((authorizeHttpRequests) ->
                        authorizeHttpRequests
                                .requestMatchers("/user").hasRole("USER")
                                .requestMatchers("/admin/pay").hasRole("ADMIN")
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                                .anyRequest().authenticated()
                )
                .formLogin((login) ->
                        login
                                //.loginPage("/loginPage")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .usernameParameter("userId")
                                .passwordParameter("passwd")
                                .loginProcessingUrl("/login_proc")
                                .successHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        System.out.println("authentication: " + authentication.getName());

                                        RequestCache requestCache = new HttpSessionRequestCache();
                                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                                        String redirectUrl = savedRequest.getRedirectUrl();

                                        response.sendRedirect(redirectUrl);
                                    }
                                })
                                .failureHandler(new AuthenticationFailureHandler() {
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                        System.out.println("exception: " + exception.getMessage());

                                        response.sendRedirect("/login");
                                    }
                                })
                                .permitAll()
                )
                .logout((logout) ->
                        logout
                                .logoutUrl("/logout")
                                .logoutSuccessUrl("/login")
                                .deleteCookies("JSESSIONID", "remember-me")
                                .addLogoutHandler(new LogoutHandler() {
                                    @Override
                                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                        HttpSession session = request.getSession(false);
                                        if (session != null) {
                                            session.invalidate();
                                        }
                                    }
                                })
                                .logoutSuccessHandler(new LogoutSuccessHandler() {
                                    @Override
                                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        System.out.println("logout: " + authentication.getName());

                                        response.sendRedirect("/login");
                                    }
                                })
                )
                .rememberMe((rememberMe) ->
                        rememberMe
                                .rememberMeParameter("remember")
                                .tokenValiditySeconds(3600)
                                //.alwaysRemember(true)
                                .userDetailsService(userDetailsService)
                )
                .sessionManagement((session) ->
                        session
                                .sessionFixation().changeSessionId()
                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                .maximumSessions(1)
                                .maxSessionsPreventsLogin(false)
                )
                .exceptionHandling((exception) ->
                        exception
                                //.authenticationEntryPoint(new AuthenticationEntryPoint() {
                                //                              @Override
                                //                              public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                                //                                  response.sendRedirect("/loginPage");
                                //                              }
                                //                          }
                                //)
                                .accessDeniedHandler(new AccessDeniedHandler() {
                                                         @Override
                                                         public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                                                             response.sendRedirect("/denied");
                                                         }
                                                     }
                                )
                );

        return http.build();
    }
}
