package com.jwyoon.oauth.model;

import java.io.Serializable;
import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;


/**
 * The persistent class for the user_list database table.
 * 
 */
@Entity
@Table(name="user_list")
@NamedQuery(name="UserList.findAll", query="SELECT u FROM UserList u")
public class UserList implements Serializable {
	private static final long serialVersionUID = 1L;

	@Id
	private String idx;

	@Column(name="user_id")
	private String userId;

	@Column(name="user_password")
	private String userPassword;

	public String getIdx() {
		return idx;
	}

	public void setIdx(String idx) {
		this.idx = idx;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getUserPassword() {
		return userPassword;
	}

	public void setUserPassword(String userPassword) {
		this.userPassword = userPassword;
	}
}