package com.common.login.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface AuthService {
	
	public Map makeJwt(Map map) throws Exception;
	
}
