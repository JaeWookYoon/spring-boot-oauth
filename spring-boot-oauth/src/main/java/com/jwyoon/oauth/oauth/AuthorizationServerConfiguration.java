package com.jwyoon.oauth.oauth;

import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.jwyoon.oauth.error.PasswordNotMatchException;
import com.jwyoon.oauth.service.UserDetailServiceImpl;

/**
 * @author user Oauth Server
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private PasswordEncoders passwordEncoders;
    @Autowired
    private UserDetailServiceImpl userDetailsService;
    @Bean
    public JdbcTokenStore jdbcTokenStore() {
		/*
		 * TokenStore tokenStore= new JwtTokenStore(accessTokenConverter());
		 * tokenStore.setApprovalStore(new InMemoryApprovalStore());
		 * tokenStore.setTokenEnhancer(jwtTokenEnhancer());
		 */
    	return new MyJdbcTokenStore(dataSource);
    }

	
	/*
	 * @Bean public TokenStore tokenStore() {// JwtTokenStore inner storeAccess �?
	 * refresh store is empty JwtTokenStore tokenStore= new
	 * JwtTokenStore(accessTokenConverter()); tokenStore.setApprovalStore(new
	 * TokenApprovalStore()); return tokenStore; }
	 */

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {

		return new JwtAccessTokenConverter();
	}
	  
    @Bean
    @Primary
    public DefaultTokenServices tokenService() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(jdbcTokenStore());
        defaultTokenServices.setAccessTokenValiditySeconds( 100 * 1);        
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setRefreshTokenValiditySeconds(100 *1 );
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        
        return defaultTokenServices;
    }

    @Bean
    @Primary
    public JdbcClientDetailsService jdbcClientDetailsService(DataSource dataSource) {
    	JdbcClientDetailsService client = new JdbcClientDetailsService(dataSource);
    	client.setPasswordEncoder(passwordEncoders);
        return client;
    }

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // OAuth2 �씤利앹꽌踰�? �옄泥댁?�� 蹂댁�? �젙蹂�?�� �꽕�젙�븯�뒗 ?���遺�?
        security.tokenKeyAccess("permitAll()");        
        security.checkTokenAccess("permitAll()");
        //security.allowFormAuthenticationForClients();
        //security.addTokenEndpointAuthenticationFilter(new CustomTokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory));
    }
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // Client �뿉 ���븳 �젙蹂�?�� �꽕�젙�븯�뒗 ?���遺�?
        clients.withClientDetails(jdbcClientDetailsService(dataSource));
    }
    
    @Bean
    protected AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(dataSource);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    	// OAuth2 �꽌踰꾧�? �옉�룞�븯湲� �쐞�븳 Endpoint�뿉 ���븳 �젙蹂�?�� �꽕�젙
        endpoints.authenticationManager(authenticationManager).tokenStore(jdbcTokenStore());
        endpoints.userDetailsService(userDetailsService);         
        endpoints.exceptionTranslator(authorizationWebResponseExceptionTranslator());
        endpoints.authorizationCodeServices(authorizationCodeServices()).tokenServices(tokenService());
        endpoints.reuseRefreshTokens(false);
        endpoints.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST,HttpMethod.PUT,HttpMethod.DELETE);
    }
    @SuppressWarnings("rawtypes")
   	public WebResponseExceptionTranslator authorizationWebResponseExceptionTranslator() {
           return new DefaultWebResponseExceptionTranslator() {

               @Override
               public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
                   Map responseMap = new HashMap();
                   if(e instanceof PasswordNotMatchException) responseMap.put("code", ((PasswordNotMatchException) e).getHttpStatus().getReasonPhrase()); 
                   responseMap.put("message", e.getMessage());
                   return new ResponseEntity(responseMap, HttpStatus.UNAUTHORIZED);
               }
           };
       }
}