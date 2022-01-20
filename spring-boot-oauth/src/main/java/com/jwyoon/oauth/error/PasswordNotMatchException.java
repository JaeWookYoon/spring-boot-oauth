package com.jwyoon.oauth.error;

import org.springframework.http.HttpStatus;

public class PasswordNotMatchException extends RuntimeException{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private HttpStatus httpStatus;

	public PasswordNotMatchException(String message) {
        super(message);
    }
	public PasswordNotMatchException(String message, Throwable cause) {
        super(message, cause);
    }	
	public PasswordNotMatchException(String message, Throwable cause,HttpStatus http) {
        super(message, cause);
        httpStatus = http;
    }
	public HttpStatus getHttpStatus() {
		return httpStatus;
	}	
}
