package com.systemsltd.common.util;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.ibm.broker.config.common.Base64;
public class Test {
	public static void main(String[] args) {

	
	String rawPassword = "GNB123"; //dcprtl123
	/*GNB*/String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdXh2VbzkwRMDTwn7zM9NfOhTfmYREP5Pf5/Kj14bfhstRBF5Fz3YR97bPyGRxfzGIpEXybCQxm0USC3Ib8HIjDZM3VrW//c2P0R8EJaM9XxuOfXRnyi+ADKlSQQZ4md3PcLAToPwTQ2U9RabDjT/O3gdQp6ocaIAyXcgj8pmCuQIDAQAB";
	// /*DCPRTL*/String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMMfIOEAZORp44fubLgnKabv0Dx2K/bG3reJ7F1UETaZNYUkEth68Zdlres33+Nn/++0B6qHBSjCRgXunKSzBTfb5dbx0GlkHw4sZW14UFG+Kib6EDsP/pn+FE0cXr3cXPie/sOVHwE+qstaoWWwt8jNThLTQyMVjRcDU7Zw0MUwIDAQAB";
	
	// /*DCPOMNI authKey*/String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDv9XW2Gw1eKvYmacXps0ykj6Ivgl5XEaLAFsqKXKOxk4FhvGHv0hyooaufJrvgdgIG52IXEqU0qO1dB8mhhoRi5sKT2Fj6ZEIFN5D/0uKu4Jq3jOV9v7iI73hJgpp0Xk8z39Gdmk3/N7Dk5CiQg3ttf091tzQIGhsgTBTHlhZw1wIDAQAB";
	
	// /*ICS authKey*/String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGU5rc9wgKsL99dmVBq1R07IR0kZUyccVUh8piYUaggLrStblmWhlSztoOlAz/Wv0jjm6kJ7Y1ZoG3Mpc5phhz+UpNAcyV7vDIRIs9XJxBXIMf53WpeLmcKCCsHoRbTxOu9lA919aLrJnxGUji/E1yoj7tNuftln1dz/LV7PsZmQIDAQAB";
	
	// /*DCPCRP*/String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTokA3K89/PVSYdP3fAQrLRNrwZQFRnK/aZ3kIQTKeZ0aGX5NRulw2/Jq+BHxJvsDmPUJwFwb9H3AklGNNatvOnXupAYxaxfzmBmj3H2SB22DEbiQZmXzcXrR0f3YglMnrig6USNRtwX+RAWDBkxZu/9YsrbThaeBQr9E/e501gwIDAQAB";
	
	//String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMMfIOEAZORp44fubLgnKabv0Dx2K/bG3reJ7F1UETaZNYUkEth68Zdlres33+Nn/++0B6qHBSjCRgXunKSzBTfb5dbx0GlkHw4sZW14UFG+Kib6EDsP/pn+FE0cXr3cXPie/sOVHwE+qstaoWWwt8jNThLTQyMVjRcDU7Zw0MUwIDAQAB";
	//String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDv9XW2Gw1eKvYmacXps0ykj6Ivgl5XEaLAFsqKXKOxk4FhvGHv0hyooaufJrvgdgIG52IXEqU0qO1dB8mhhoRi5sKT2Fj6ZEIFN5D/0uKu4Jq3jOV9v7iI73hJgpp0Xk8z39Gdmk3/N7Dk5CiQg3ttf091tzQIGhsgTBTHlhZw1wIDAQAB";
	//String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCF3EDetE0IR/73JZiW3fKk9MZduo8jkC/XR0uaCH2AMxLJgUzHTLrsUDb9nFsJ2GaGwYXDi5d3Zj8g7b4HGIMAwXxhlqAoJpfO7w2jb4ezZrSELYTNHM+yWeZkMuj4SpBH8cDf25Y321N+aEcma/SqINxH420W/Sic8TVv/0LYrQIDAQAB";
	encryptTest_UBL(rawPassword,publicKey,"feafc2dd-b819-46a7-937f-f51621d75057");
	
}
	public static byte[] generateSymmetricKey(Long keySize, String keyAlgo) {
		byte[] generatedKey = null;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);
			keyGen.init(keySize.intValue());
			generatedKey = keyGen.generateKey().getEncoded();
	} catch (Exception ex) {
		ex.printStackTrace();
	}
		return generatedKey;
	}
	public static byte[] encrypt(byte[] data, String algorithm, byte[] key, byte[] iv) {
	byte[] encryptedBytes = null;
	try {
		String[] algo = algorithm.split("/");
		SecretKeySpec secretKey = new SecretKeySpec(key, algo[0]);
		Cipher cipher = Cipher.getInstance(algorithm);
		if (iv == null) {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		}
		encryptedBytes = cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedBytes;
	}
	public static byte[] encryptAsymmetric(byte[] data, String algorithm, byte[] key) {
		byte[] encryptedBytes = null;
		try {
			String[] algo = algorithm.split("/");
			KeyFactory kf = KeyFactory.getInstance(algo[0]);
			PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(key));
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, pk);
			encryptedBytes = cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedBytes;
	}
	private static void encryptTest_UBL(String rawPassword, String publicKey,String RefNo) {
		long keySize = 128;
		String algorithm = "AES";
		System.out.println("************Start*********************************************");
		String password = rawPassword+":"+RefNo;
		byte[] key = generateSymmetricKey(keySize, algorithm);
		byte[] encryptedPassword = encrypt(password.getBytes(), "AES/ECB/PKCS5Padding", key, null);
		System.out.println("password: " + Base64.encode(encryptedPassword));
		byte[] encryptedKey = encryptAsymmetric(key, "RSA/ECB/PKCS1Padding", Base64.decode(publicKey));
		System.out.println("authKey: " + Base64.encode(encryptedKey));
		System.out.println("************end*********************************************");
	}
}