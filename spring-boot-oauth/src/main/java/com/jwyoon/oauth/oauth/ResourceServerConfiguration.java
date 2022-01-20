package com.jwyoon.oauth.oauth;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

/**
 *
 * @author user API Server
 */
@Configuration // API �꽌踰� �씤利�, 沅뚰�? �꽕�젙
//@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	@Resource(name = "dataSource")
	private DataSource dataSource;
	
//	@Bean
//    public TokenStore jdbcTokenStore() {
//    	return new MyJdbcTokenStore(dataSource);
//    }
	private String resourceId = "rest-api";
	@Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        // @formatter:off
        resources.resourceId(resourceId);
        // @formatter:on
    }
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		// �옄�썝�꽌踰� �젒洹쇨?���븳 �꽕�젙
		http.headers().frameOptions().disable();
		http.authorizeRequests().antMatchers("/", "/**", "/callback").permitAll().antMatchers("/oauth/**")
				.hasAnyAuthority("ROLE_USER", "ROLE_ADMIN").antMatchers("/user").authenticated().antMatchers("/admin")
				.authenticated();

	}
	
//	@Bean
//	public TokenStore tokenStore() {
//		return new JwtTokenStore(accessTokenConverter());
//	}
//
//	@Bean
//	public JwtAccessTokenConverter accessTokenConverter() {
//
//		return new JwtAccessTokenConverter();
//	}
}