package com.sh.auth.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sh.auth.crypto.KeyInfo;
import com.sh.auth.crypto.RSAKeys;
import com.sh.auth.crypto.RSARepository;
import com.sh.auth.provider.User;
import com.sh.auth.service.SignInService;

@Service
public class SignInServiceImpl implements SignInService {

	@Autowired
	private RSAKeys rsaKeys;
	
	@Autowired
	private RSARepository repo;
	
	
	@Override
	public boolean createUser(User user) 
	{
		
		try
		{
			String cert = rsaKeys.signContent(user.getPwd().getBytes());
			KeyInfo key = new KeyInfo();
			key.setUser(user.getName());
			key.setKey(cert);
			key.setTimestamp(System.currentTimeMillis());
			key.setChipher(rsaKeys.chipher(user.getPwd()));
			repo.writeCert(key);
			return true;
		}
		catch(Exception e)
		{
			return false;
		}
	}
	
}
