/**
 * 
 */
package com.ncsu.csc574.securitymanagement;

/**
 * This is a factory class that returns default SecurityManager class
 * 
 * @author Harsha
 * 
 */
public class SecurityManagerFactory {
	private static ISecurityManager instance = null;

	public static ISecurityManager getInstance(String passphrase,
			boolean isMutAuthRequired, String keyStoreFilename,
			String trustStoreFilename) throws Exception {
		// fix this
		if (instance == null) {
			instance = new SecurityManager(passphrase, isMutAuthRequired,
					keyStoreFilename, trustStoreFilename);
		}
		return instance;
	}

	public static ISecurityManager getInstance() throws Exception {
		if (instance == null) {
			throw new Exception(
					"Security manager not initialized. Use other getInstance method to initialize it");
		}
		return instance;
	}
}