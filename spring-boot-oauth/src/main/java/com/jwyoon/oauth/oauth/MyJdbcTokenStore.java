package com.jwyoon.oauth.oauth;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.stereotype.Component;
@Component
public class MyJdbcTokenStore extends JdbcTokenStore{

	@Autowired
    private DataSource dataSource;
	
	public MyJdbcTokenStore(DataSource dataSource) {
		super(dataSource);
		// TODO Auto-generated constructor stub
	}		
}
