package com.common.login.service.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.common.login.mapper.MemberMapper;
import com.common.login.service.MemberService;

@Service
public class MemberServiceImpl implements MemberService {

	@Autowired
	private MemberMapper memberMapper;
	
	@Override
	public UserDetails loadUserByUsername(String account) throws UsernameNotFoundException {
		
		
		Map userMap = memberMapper.getUser(account);

        List<GrantedAuthority> authorities = new ArrayList<>();

        authorities.add(new SimpleGrantedAuthority("ROLE_MEMBER"));

        return new User(userMap.get("id").toString(), userMap.get("pw").toString(), authorities);
	}

	@Override
	public Integer save(Map memerToMap) throws UsernameNotFoundException {
		//Member member = memberTO.toEntity();
        //member.setLastAccessDt(LocalDateTime.now());
        //member.setRegDt(LocalDateTime.now());
        //
        //// ¾ÏÈ£È­
        //BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        //member.setPassword(passwordEncoder.encode(member.getPassword()));
        //return memberDao.save(member).getId();
		return 0;
	}

}
