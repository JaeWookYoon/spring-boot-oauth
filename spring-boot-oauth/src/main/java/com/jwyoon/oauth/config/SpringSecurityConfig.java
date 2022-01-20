package com.jwyoon.oauth.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.jwyoon.oauth.filter.LoginSuccessHander;
import com.jwyoon.oauth.oauth.PasswordEncoders;
import com.jwyoon.oauth.service.UserDetailServiceImpl;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired 
	private UserDetailServiceImpl userDetailsService;
    @Autowired
    private AccessDeniedHandler accessDeniedHandler;
    @Autowired
    private PasswordEncoders passwordEncoders;
    @Autowired
    private LoginSuccessHander loginSuccessHandler;    
    // roles admin allow to access /admin/**
    // roles user allow to access /user/**
    // custom 403 access denied handler
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	
        http	.csrf().disable()
        		.headers().frameOptions().disable()
        		.and()
                .authorizeRequests()
                .antMatchers("/home", "/about","/callback","/request").permitAll()
                .antMatchers("/oauth/token").permitAll()
                //.antMatchers("/oauth/**").hasAnyAuthority("ROLE_USER","ROLE_ADMIN")
                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                .antMatchers("/user/**").hasAnyRole("USER")                 
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler);
    }
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    //AuthenticationManager Initiated
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {    	
    	auth.parentAuthenticationManager(authenticationManagerBean()).userDetailsService(userDetailsService)
    	.passwordEncoder(passwordEncoders);    	
    }
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        List<String> allowOrigin = new ArrayList<>();
        allowOrigin.add("http://localhost:8081");
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowOrigin);
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    //Spring Boot configured this already.
    @Override
    public void configure(WebSecurity web) throws Exception {
        web        
        .ignoring()
                .antMatchers("/resources/**", "/static/**", "*/css/**", "/js/**", "/images/**,webjars/**");
    }

}
