package com.ncsu.csc574.securitymanagement;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

public interface ISecurityManager {
	
	/**
	 * Invoked from launcher.
	 * It generates master key using the passphrase.
	 * @param passPhrase
	 */
	public void init(String passPhrase, boolean isMutAuthRequired, String keyStoreFileName, String trustStoreFileName);
	
	
	public boolean isMutAuthRequired();
	
	
	public String encrypt(SecretKeySpec key, String msg);
	
	
	public String decrypt(SecretKeySpec key, String msg);
	
	/**
	 * This method uses the loaded masterkey for generating user specific key
	 * @param userName
	 * @param domainName
	 * @return
	 */
	public SecretKeySpec getUserMailBoxKey(String userName, String domainName);
	
	public String generateHash( String ... arg );
	
	public KeyManager[] getkeyManagerList();
	
	public TrustManager[] getTrustStoreManagerList();

}
