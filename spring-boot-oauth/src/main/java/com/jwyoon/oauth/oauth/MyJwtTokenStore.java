package com.jwyoon.oauth.oauth;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Component;
@Component
public class MyJwtTokenStore extends JwtTokenStore{

	@Value("${spring.redis.host}")
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;
        
    private AccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();
    
//    @Autowired
//    private RedisTemplate redisTemplate;
    @Autowired
    private JwtAccessTokenConverter jwtTokenEnhancer;
    
    private JsonParser objectMapper = JsonParserFactory.create();
    
	/*
	 * private SignatureVerifier verifier;
	 * 
	 * private ApprovalStore approvalStore;
	 */
//    
//    @Bean
//    @ConditionalOnMissingBean(name = "redisTemplate")
//    public RedisTemplate<?, ?> redisTemplate() {
//        RedisTemplate<byte[], byte[]> redisTemplate = new RedisTemplate<>();
//        redisTemplate.setConnectionFactory(jedisConnectionFactory());
//        return redisTemplate;
//    }

	/*
	 * @Bean public void setVerifier(SignatureVerifier verifier) { this.verifier =
	 * verifier; } private TokenStore tokenStore() { if (tokenStore == null) { if
	 * (accessTokenConverter() instanceof JwtAccessTokenConverter) { this.tokenStore
	 * = new JwtTokenStore((JwtAccessTokenConverter) accessTokenConverter()); } else
	 * { this.tokenStore = new InMemoryTokenStore(); } } return this.tokenStore; }
	 */
	/*
	 * @Bean private ApprovalStore approvalStore() { if (approvalStore == null &&
	 * tokenStore() != null && !isApprovalStoreDisabled()) { TokenApprovalStore
	 * tokenApprovalStore = new TokenApprovalStore();
	 * tokenApprovalStore.setTokenStore(tokenStore()); this.approvalStore =
	 * tokenApprovalStore; } return this.approvalStore; }
	 */
//    @Bean
//    JedisConnectionFactory jedisConnectionFactory() {
//        return new JedisConnectionFactory();
//    }
	public MyJwtTokenStore(JwtAccessTokenConverter jwtTokenEnhancer) {
		super(jwtTokenEnhancer);
		this.jwtTokenEnhancer = jwtTokenEnhancer;
	}
	
	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
//		String userId = authentication.getUserAuthentication().getName();
//		String clientId = authentication.getOAuth2Request().getClientId();
//		HashOperations<String, Object, Object> stringObjectObjectHashOperations = redisTemplate.opsForHash();
//		
//	    stringObjectObjectHashOperations.put(userId, "accessToken", token);	    	
	}
	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
//		String userId = authentication.getUserAuthentication().getName();
//		String clientId = authentication.getOAuth2Request().getClientId();
//		HashOperations<String, Object, Object> stringObjectObjectHashOperations = redisTemplate.opsForHash();
//		
//	    stringObjectObjectHashOperations.put(userId, "refreshToken", refreshToken);
		
	}
	public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		return tokenConverter.convertAccessToken(token, authentication);
	}

	/*
	 * protected Map<String, Object> decode(String token) { try { Jwt jwt =
	 * JwtHelper.decodeAndVerify(token, verifier); String content = jwt.getClaims();
	 * Map<String, Object> map = objectMapper.parseMap(content); if
	 * (map.containsKey(tokenConverter.EXP) && map.get(tokenConverter.EXP)
	 * instanceof Integer) { Integer intValue = (Integer)
	 * map.get(tokenConverter.EXP); map.put(tokenConverter.EXP, new Long(intValue));
	 * } return map; } catch (Exception e) { throw new
	 * InvalidTokenException("Cannot convert access token to JSON", e); } }
	 */
	/*
	 * @Override public OAuth2AccessToken readAccessToken(String tokenValue) {
	 * OAuth2AccessToken accessToken =
	 * jwtTokenEnhancer.extractAccessToken(tokenValue,decode(tokenValue)); if
	 * (jwtTokenEnhancer.isRefreshToken(accessToken)) { throw new
	 * InvalidTokenException("Encoded token is a refresh token"); } return
	 * accessToken; }
	 * 
	 * @Override public OAuth2RefreshToken readRefreshToken(String tokenValue) {
	 * OAuth2AccessToken encodedRefreshToken =
	 * jwtTokenEnhancer.extractAccessToken(tokenValue,decode(tokenValue));
	 * OAuth2RefreshToken refreshToken = createRefreshToken(encodedRefreshToken); if
	 * (approvalStore != null) { OAuth2Authentication authentication =
	 * readAuthentication(tokenValue); if (authentication.getUserAuthentication() !=
	 * null) { String userId = authentication.getUserAuthentication().getName();
	 * String clientId = authentication.getOAuth2Request().getClientId();
	 * Collection<Approval> approvals = approvalStore.getApprovals(userId,
	 * clientId); Collection<String> approvedScopes = new HashSet<String>(); for
	 * (Approval approval : approvals) { if (approval.isApproved()) {
	 * approvedScopes.add(approval.getScope()); } } if
	 * (!approvedScopes.containsAll(authentication.getOAuth2Request().getScope())) {
	 * return null; } } } return refreshToken; }
	 */
	private OAuth2RefreshToken createRefreshToken(OAuth2AccessToken encodedRefreshToken) {
		if (!jwtTokenEnhancer.isRefreshToken(encodedRefreshToken)) {
			throw new InvalidTokenException("Encoded token is not a refresh token");
		}
		if (encodedRefreshToken.getExpiration()!=null) {
			return new DefaultExpiringOAuth2RefreshToken(encodedRefreshToken.getValue(),
					encodedRefreshToken.getExpiration());			
		}
		return new DefaultOAuth2RefreshToken(encodedRefreshToken.getValue());
	}
}
