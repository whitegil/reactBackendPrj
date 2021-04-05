package com.common.login.service.impl;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.common.login.service.AuthService;
import com.common.login.service.LoginService;
import com.common.login.service.dao.LoginDAO;

@Service("authService")
public class AuthServiceImpl implements AuthService {

	@Override
	public Map makeJwt(Map map) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

}



