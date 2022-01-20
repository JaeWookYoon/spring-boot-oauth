package com.jwyoon.oauth.repository;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.jwyoon.oauth.model.UserAuth;
import com.jwyoon.oauth.model.UserList;

@Repository
@Transactional
public class UserListRepository {

	@PersistenceContext
	private EntityManager entityManager;
	
	public UserList findUserById(String id) {
		Query q = entityManager.createNativeQuery("select * from user_list where user_id=:id",UserList.class).setParameter("id", id);
		UserList user = (UserList)q.getSingleResult();
		return user;
	}
	public List<UserAuth> findUserAuthById(String id) {
		Query q = entityManager.createNativeQuery("select * from user_auth where id=:id",UserAuth.class).setParameter("id", id);
		List<UserAuth> user = (List<UserAuth>)q.getResultList();
		return user;
	}
}
