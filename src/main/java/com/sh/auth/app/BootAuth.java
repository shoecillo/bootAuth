package com.sh.auth.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.sh.auth.crypto.RSAKeys;
import com.sh.auth.crypto.RSARepository;


@Configuration
@ComponentScan("com.sh.auth")
@SpringBootApplication
public class BootAuth {
	
	@Value("${keys.keystore.path}")
	private  String ksPath;
	
	
	@Value("${keys.keystore.pwd}")
	private String pwd;
	
	@Value("${keys.keystore.alias}")
	private String alias;
	
	@Value("${keys.repo.path}")
	private  String REP_PATH;
	
	@Value("${keys.repo.cookie.name}")
	private String COOKIE_NAME;
	
	public static void main(String[] args)
	{
		SpringApplication.run(BootAuth.class, args);
	}
	
	@Bean
	public RSAKeys configKey()
	{
		return new RSAKeys(ksPath, pwd, alias);
	}
	
	@Bean
	public RSARepository configRepo()
	{
		return new RSARepository(REP_PATH, COOKIE_NAME);
	}
	
}
