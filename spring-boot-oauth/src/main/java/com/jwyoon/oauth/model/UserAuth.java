package com.jwyoon.oauth.model;

import java.io.Serializable;
import javax.persistence.*;
/**
 * The persistent class for the user_auth database table.
 * 
 */
@Entity
@Table(name="user_auth")
@NamedQuery(name="UserAuth.findAll", query="SELECT u FROM UserAuth u")
public class UserAuth implements Serializable {
	private static final long serialVersionUID = 1L;

	@Id
	private String idx;

	private String auth;	

	private String id;

	public String getIdx() {
		return this.idx;
	}

	public void setIdx(String idx) {
		this.idx = idx;
	}

	public String getAuth() {
		return this.auth;
	}

	public void setAuth(String auth) {
		this.auth = auth;
	}	

	public String getId() {
		return this.id;
	}

	public void setId(String id) {
		this.id = id;
	}
}