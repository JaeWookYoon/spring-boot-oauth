package com.jwyoon.oauth.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
@Component
public class LoginSuccessHander implements AuthenticationSuccessHandler {

	@SuppressWarnings("deprecation")
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		HttpSession session = request.getSession();
		String username = request.getParameter("username");
		String password = request.getParameter("password");

		session.setAttribute("username", username);
		session.setAttribute("password", password);
		String redirectUrl = "/callback";
		response.sendRedirect(request.getContextPath() + "/oauth/authorize?client_id=" + username + "&response_type=code&redirect_uri=" + redirectUrl);
	}
}
