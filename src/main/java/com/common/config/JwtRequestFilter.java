package com.common.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import com.common.util.JwtUtil;


public class JwtRequestFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
		
		Cookie[] cookies = httpServletRequest.getCookies();
		Cookie loginToken = null;
		
		for(Cookie cookie : cookies){
            if(cookie.getName().equals("loginToken")){
            	loginToken = cookie;
            }
        }

        String username = null;
        String jwt = null;
        String refreshJwt = null;
        String refreshUname = null;

        try{
            if(loginToken != null){
                jwt = loginToken.getValue();
                username = JwtUtil.getSubject(jwt);
            }else {
            	throw new Exception(); 
            }
            
//            if(true) {
//            	throw new Exception(); 
//            }
            
//			권한관리로 들어올경우 쿠키는 살아있고 세션이 없을 경우 재 로그인
//			향후 스프링 스큐리티가 붙을시에 여기에 security 내용으로 convert되는 내용을 담아야됨
//			컨버트가 안될경우, 올바른 인증상태가 아닐경우 403 error로 자동치환
//            if(username != null){
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//                if(jwtUtil.validateToken(jwt,userDetails)){
//                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
//                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
//                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//                }
//            }
        
           
            
        }catch(Exception e){
        	//임시로 로그인 정보가 없을경우 에러 처리한다.
        	throw new ServletException(); 
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
	}



}
