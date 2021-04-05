package com.common.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.interceptor.DefaultTransactionAttribute;
import org.springframework.transaction.interceptor.RollbackRuleAttribute;
import org.springframework.transaction.interceptor.RuleBasedTransactionAttribute;
import org.springframework.transaction.interceptor.TransactionInterceptor;

@Aspect
@Configuration
@EnableAspectJAutoProxy
public class TransactionConfig {

	private static final Logger LOGGER = LoggerFactory.getLogger(TransactionConfig.class);

	private static final int TX_METHOD_TIMEOUT = 3;

	private static final String AOP_POINTCUT_EXPRESSION = "execution(* com.common.*.*ServiceImpl(..))";

	@Autowired

	private PlatformTransactionManager transactionManager;
	// private DataSourceTransactionManager transactionManager;

	@Bean

	public TransactionInterceptor txAdvice() {

		TransactionInterceptor txAdvice = new TransactionInterceptor();
		Properties txAttributes = new Properties();

		List<RollbackRuleAttribute> rollbackRules = new ArrayList<RollbackRuleAttribute>();
		rollbackRules.add(new RollbackRuleAttribute(Exception.class));

		DefaultTransactionAttribute readOnlyAttribute = new DefaultTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED);
		readOnlyAttribute.setReadOnly(true);
		readOnlyAttribute.setTimeout(TX_METHOD_TIMEOUT);

		RuleBasedTransactionAttribute writeAttribute = new RuleBasedTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED, rollbackRules);

		writeAttribute.setTimeout(TX_METHOD_TIMEOUT);

		String readOnlyTransactionAttributesDefinition = readOnlyAttribute.toString();
		String writeTransactionAttributesDefinition = writeAttribute.toString();

		// read-only
		txAttributes.setProperty("select*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("list*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("count*", readOnlyTransactionAttributesDefinition);

		// write rollback-rule
		txAttributes.setProperty("*", writeTransactionAttributesDefinition);

		txAdvice.setTransactionAttributes(txAttributes);

		txAdvice.setTransactionManager(transactionManager);
		return txAdvice;

	}

	@Bean
	public Advisor txAdviceAdvisor() {

		AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();

		pointcut.setExpression(AOP_POINTCUT_EXPRESSION);

		return new DefaultPointcutAdvisor(pointcut, txAdvice());

	}

}
