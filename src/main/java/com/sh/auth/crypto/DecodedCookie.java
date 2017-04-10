package com.sh.auth.crypto;

public class DecodedCookie {
	
	private String user;
	
	private String cert;
	
	private String creation;

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getCert() {
		return cert;
	}

	public void setCert(String cert) {
		this.cert = cert;
	}

	public String getCreation() {
		return creation;
	}

	public void setCreation(String creation) {
		this.creation = creation;
	}
	
	
	
}
