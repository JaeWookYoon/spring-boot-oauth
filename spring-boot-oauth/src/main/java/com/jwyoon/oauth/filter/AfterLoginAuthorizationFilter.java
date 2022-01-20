package com.jwyoon.oauth.filter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class AfterLoginAuthorizationFilter {

	@SuppressWarnings({ "unused", "resource", "deprecation", "unchecked", "null", "rawtypes" })
	private String obtainAccessToken(String username, String password) throws Exception {
		HttpClient client = new DefaultHttpClient();

		List<NameValuePair> pairs = new ArrayList<NameValuePair>();
		System.out.println("username and password = " + username + " , " + password);
		String redirectUrl = "http://localhost:8080/callback";
		HttpGet get = new HttpGet("http://localhost:8080/oauth/authorize?client_id=" + username + "&redirect_uri="
				+ redirectUrl + "&response_type=code");

		HttpEntity entity = new UrlEncodedFormEntity(pairs, "UTF-8");

		HttpResponse result = client.execute(get);

		BufferedReader br = new BufferedReader(new InputStreamReader(result.getEntity().getContent()));
		StringBuffer strBuf = new StringBuffer();
		String str = "";
		while ((str = br.readLine()) != null) {
			strBuf.append(str);
		}

		return strBuf.toString();
	}

	/*@After(value = "execution(* LoginSuccessHander.on*(..))")*/
	public void onAfterLogServiceAccess(JoinPoint joinPoint) {
		try{
			Thread.sleep(1000);
		}catch(Exception e) {
			
		}
		Object[] o = joinPoint.getArgs();
		UsernamePasswordAuthenticationToken userToken = null;
		new RuntimeException();
		for (Object obj : o) {
			if(obj instanceof UsernamePasswordAuthenticationToken) {				
				userToken = (UsernamePasswordAuthenticationToken) obj;
				UserDetails user = (UserDetails) userToken.getPrincipal();
				try {
					String result = obtainAccessToken(user.getUsername(),user.getPassword());
					System.out.println("Result = "+result);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}			
		}
	}
}
