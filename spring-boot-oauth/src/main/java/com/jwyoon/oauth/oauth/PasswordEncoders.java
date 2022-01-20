package com.jwyoon.oauth.oauth;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.Base64;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.jwyoon.oauth.error.PasswordNotMatchException;

@Component
public class PasswordEncoders implements PasswordEncoder {
	private BCryptPasswordEncoder passwordEncoder;

	public PasswordEncoders() {
		this.passwordEncoder = new BCryptPasswordEncoder();
	}

	public PasswordEncoders(BCryptPasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public String encode(CharSequence rawPassword) {
		return passwordEncoder.encode(rawPassword);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if(rawPassword == null) {
			throw new PasswordNotMatchException("패스워드를 입력하세요.",null,HttpStatus.BAD_REQUEST);
		}
		System.out.println(rawPassword + " PASSWORD = " + encodedPassword);
		boolean result = passwordEncoder.matches(rawPassword,encodedPassword);
		
		if(!result) { 			
			throw new PasswordNotMatchException("password not matched",null,HttpStatus.BAD_REQUEST);			
		}
		return result;
	}

	public static void main(String[] args) {
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String s = "client:{noop}1234";
		String a = "1234";
		String b = "{noop}1234";
		System.out.println(passwordEncoder.encode(a));
		System.out.println(passwordEncoder.encode(b));
		byte[] encodedAuth = Base64.encodeBase64(s.getBytes(StandardCharsets.ISO_8859_1));
        String authHeader = "Basic " + new String(encodedAuth);
		//System.out.println(passwordEncoder.encode(s));
        System.out.println(authHeader);
	}
	//$2a$10$QNUU6chh.WnLV0/QStE6YeoMfWSUkW6FZHYicAKNu9D5Kfy/1NjNi
}