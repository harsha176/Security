package com.ncsu.csc574.securitymanagement;

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

public interface ISecurityManager {
	
	/**
	 * Invoked from launcher.
	 * It generates master key using the passphrase.
	 * @param passPhrase
	 */
	public void init(String passPhrase, boolean isMutAuthRequired, String keyStoreFileName, String trustStoreFileName) throws Exception;
	
	
	public boolean isMutAuthRequired();
	
	
	public String encrypt(Key key, String msg) throws Exception;
	
	
	public String decrypt(Key key, String msg) throws Exception;
	
	/**
	 * This method uses the loaded masterkey for generating user specific key
	 * @param userName
	 * @param domainName
	 * @return
	 */
	public Key getUserMailBoxKey(String userName, String domainName) throws Exception;
	
	public String generateHash( String ... arg ) throws Exception ;
	
	public KeyManager[] getkeyManagerList();
	
	public TrustManager[] getTrustStoreManagerList();

}
