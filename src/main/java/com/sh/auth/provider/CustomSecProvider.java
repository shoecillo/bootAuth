package com.sh.auth.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.sh.auth.crypto.KeyInfo;
import com.sh.auth.crypto.RSAKeys;
import com.sh.auth.crypto.RSARepository;


@Component
public class CustomSecProvider implements AuthenticationProvider  {
	
	@Autowired
	private RSAKeys keys;
	
	@Autowired
	private HttpServletRequest req;
	
	@Autowired
	private HttpServletResponse resp;
	
	@Autowired
	private RSARepository repo;
	
	
	@Override
	public Authentication authenticate(Authentication auth) throws AuthenticationException 
	{
		
		final String pwd = (String) auth.getCredentials();
		final String user = auth.getName();
		
		System.out.println(req.getRequestURI());
		
		Collection<? extends GrantedAuthority> authorities = buildAuthorities();
		
			
			try 
			{
				final List<KeyInfo> lsKeys = repo.readKeys();
				
				Cookie coo = repo.isCookiePresent(req);
				if(coo != null)
				{
					if(keys.validateCookie(coo))
					{
						KeyInfo inf = repo.readKeys(keys.decodeCookie(coo).getUser());
						return new UsernamePasswordAuthenticationToken(inf.getUser(), inf.getChipher(), authorities);
					}
				}
				else
				{
					for(KeyInfo k : lsKeys)
					{
						if(k.getUser().equals(user))
						{
							if(keys.authenticate(k.getKey(), pwd))
							{
								resp.addCookie(repo.createCookie(user));
								return new UsernamePasswordAuthenticationToken(user, pwd, authorities);
							}
							else
							{
								throw new BadCredentialsException("Wrong credentials");
							}
						}
					}
				}
			} catch (Exception e) {
				
				throw new BadCredentialsException("Wrong credentials");
			}
			return null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
	
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	
	private List<Role> buildAuthorities()
	{
		 Role r = new Role();
         r.setName("ROLE_USER");
         List<Role> roles = new ArrayList<Role>();
         roles.add(r);
         return roles;
	}
	
	

}
