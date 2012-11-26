package com.ncsu.csc574.securitymanagement;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.codec.binary.Base64;

public class SecurityManager implements ISecurityManager {
	private static final String COMM_STORE_PASSPHRASE = "qwerty";
	private static final String KEY_ALGORITHM_TYPE = "PKIX";
	private String passphrase;
	private boolean isMutAuthRequired;
	private KeyManagerFactory km;
	private TrustManagerFactory tm;
	private Key masterkey;

	public SecurityManager(String passphrase, boolean isMutAuthRequired,
			String keyStoreFilename, String trustStoreFilename)
			throws Exception {
		init(passphrase, isMutAuthRequired, keyStoreFilename,
				trustStoreFilename);
	}

	/**
	 * This function initializes security module 1. open master keystore file to
	 * load masterkey 2. initialize keystore and trustStore managers
	 */
	@Override
	public void init(String passphrase, boolean isMutAuthRequired,
			String keyStoreFileName, String trustStoreFileName)
			throws Exception {

		this.isMutAuthRequired = isMutAuthRequired;
		this.passphrase = passphrase;

		// open master keystore file
		KeyStore masterKeyStore = KeyStore.getInstance("JCEKS");
		masterKeyStore.load(
				ClassLoader.getSystemResourceAsStream("emaster.jks"), null);
		masterkey = masterKeyStore.getKey("emaster", passphrase.toCharArray());

		// initialize keystore and trustStore managers
		/* Initialize keyManagerFactory */
		km = KeyManagerFactory.getInstance(KEY_ALGORITHM_TYPE);
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(ClassLoader.getSystemResourceAsStream(keyStoreFileName), null);
		km.init(ks, COMM_STORE_PASSPHRASE.toCharArray());

		/* Initialize TrustManagerFactory */
		tm = TrustManagerFactory.getInstance(KEY_ALGORITHM_TYPE);
		KeyStore ts = KeyStore.getInstance("JKS");
		ts.load(ClassLoader.getSystemResourceAsStream(trustStoreFileName), null);
		tm.init(ts);
	}

	@Override
	public boolean isMutAuthRequired() {
		return isMutAuthRequired;
	}

	/**
	 * 
	 */
	@Override
	public String encrypt(Key key, String msg) throws Exception {
		if (key == null) {
			throw new Exception("Invalid key");
		} else if (key.getEncoded().length != 16) {
			throw new Exception("Invalid key length " + key.getEncoded().length);
		}

		byte[] cleartext = msg.getBytes("UTF-8");
		// encryption
		Cipher cipher = Cipher.getInstance("AES"); // cipher is not thread safe
		cipher.init(Cipher.ENCRYPT_MODE, key);
		Base64 base64 = new Base64();
		return base64.encodeAsString(cipher.doFinal(cleartext));

	}

	@Override
	public String decrypt(Key key, String msg) throws Exception{
		if (key == null) {
			throw new Exception("Invalid key");
		} else if (key.getEncoded().length != 16) {
			throw new Exception("Invalid key length " + key.getEncoded().length);
		}
		
		// decryption
		byte[] base64Msg = Base64.decodeBase64(msg);
		Cipher dCiph = Cipher.getInstance("AES");
		dCiph.init(Cipher.DECRYPT_MODE, key);
		return new String(dCiph.doFinal(base64Msg), "UTF-8");
	}

	@Override
	public Key getUserMailBoxKey(String username, String domainName) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(masterkey);
		byte[] keyMaterial = mac.doFinal((username + domainName).getBytes());
		return new SecretKeySpec(keyMaterial, 0, 16, "AES");
	}

	
	
	@Override
	public String generateHash(String... arg) throws Exception{
		String temp = new String();
		for (int i = 0; i < arg.length; i++) {
		  temp = temp + arg[i]; 
		}
		
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(masterkey);
		byte[] keyMaterial = mac.doFinal(temp.getBytes());
		return new String (keyMaterial , "UTF-8");

	}

	@Override
	public KeyManager[] getkeyManagerList() {
		return km.getKeyManagers();
	}

	@Override
	public TrustManager[] getTrustStoreManagerList() {
		return tm.getTrustManagers();
	}

}
