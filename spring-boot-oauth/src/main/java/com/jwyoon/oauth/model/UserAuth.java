package com.jwyoon.oauth.model;

import java.io.Serializable;
import javax.persistence.*;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
/**
 * The persistent class for the user_auth database table.
 * 
 */
@Getter
@Setter
@EqualsAndHashCode(of={"id"})
@Entity
@Table(name="user_auth")
@NamedQuery(name="UserAuth.findAll", query="SELECT u FROM UserAuth u")
public class UserAuth implements Serializable {
	private static final long serialVersionUID = 1L;

	@Id
	private String id;
	
	private String auth;		
	
}