package com.common.login.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface MemberService extends UserDetailsService {


	public UserDetails loadUserByUsername(String account) throws UsernameNotFoundException;

	
	public Integer save(Map memerToMap) throws UsernameNotFoundException;
}
