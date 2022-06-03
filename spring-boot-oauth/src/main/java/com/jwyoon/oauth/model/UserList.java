package com.jwyoon.oauth.model;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;


/**
 * The persistent class for the user_list database table.
 * 
 */
@Getter
@Setter
@EqualsAndHashCode(of={"userId"})
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
}