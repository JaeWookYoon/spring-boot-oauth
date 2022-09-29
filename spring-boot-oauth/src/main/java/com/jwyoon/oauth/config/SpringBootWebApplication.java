package com.jwyoon.oauth.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

//http://www.thymeleaf.org/doc/articles/layouts.html
@EnableAutoConfiguration
@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })
public class SpringBootWebApplication {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(SpringBootWebApplication.class, args);
	}
} 