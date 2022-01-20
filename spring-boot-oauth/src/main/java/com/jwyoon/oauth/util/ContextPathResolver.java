package com.jwyoon.oauth.util;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;

import com.jwyoon.oauth.oauth.PasswordEncoders;

public class ContextPathResolver {

    public String contextPathResolve(HttpServletRequest request) {
        StringBuffer url = request.getRequestURL();

        return url.toString().replace(request.getRequestURI(), "");
    }
    public static void main(String[]args) {
    	PasswordEncoders pa = new PasswordEncoders();
    	System.out.println(pa.encode("1234"));
    	String auth = "client:1234";
    	System.out.println(Arrays.toString(Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1))))
    	;
    }
}