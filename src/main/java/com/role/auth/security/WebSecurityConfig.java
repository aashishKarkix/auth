package com.role.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            auth -> auth
                .requestMatchers("/admin/**")
                .hasAuthority("ROLE_ADMIN")
                .requestMatchers("/user/**")
                .hasAuthority("ROLE_USER")
                .requestMatchers("/login", "/error")
                .permitAll()
                .anyRequest()
                .authenticated())
        .cors(Customizer.withDefaults()).csrf(
            (csrf) -> csrf
                .ignoringRequestMatchers("/**")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .formLogin(form -> form.loginPage("/login")
            .successHandler(authenticationSuccessHandler())
            .permitAll())
        .logout(LogoutConfigurer::permitAll)
        .exceptionHandling(exception -> exception.accessDeniedPage("/error"));

    return http.build();
  }

  @Bean
  public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    UserDetails user = User
        .withUsername("user")
        .password(passwordEncoder.encode("password"))
        .roles("USER")
        .build();
    UserDetails admin = User
        .withUsername("admin")
        .password(passwordEncoder.encode("password"))
        .roles("ADMIN")
        .build();
    return new InMemoryUserDetailsManager(user, admin);
  }

  @Bean
  public AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new CustomAuthenticationSuccessHandler();
  }

  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }
}
