package com;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.support.ErrorPageFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

import com.common.config.JwtRequestFilter;
import com.common.config.TransactionConfig;

@SpringBootApplication
@Import({ TransactionConfig.class })
@ComponentScan
public class TestApplication {

	public static void main(String[] args) {
		SpringApplication.run(TestApplication.class, args);
	}
	
	@Bean
	public FilterRegistrationBean setFilterRegistration() {
		FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean(new JwtRequestFilter());
		
		filterRegistrationBean.addUrlPatterns("/api/auth/check"); // string 여러개를 가변인자로 받는 메소드
		
		return filterRegistrationBean;
	}
	
}
