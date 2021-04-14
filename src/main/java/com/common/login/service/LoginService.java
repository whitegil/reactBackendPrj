package com.common.login.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

public interface LoginService {
	
	public Map userLogin(Map map) throws Exception;

	public Map userCheck(Map map) throws Exception;
	
	public UserDetails loadUserByUsername(String username) throws Exception;

	public Map insertUser(Map map) throws Exception;

	public Map updateGoogleLogin(Map map) throws Exception;
	
}



