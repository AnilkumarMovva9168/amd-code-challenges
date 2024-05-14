package com.amd.poc;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.security.PrivateKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AmdImageDecryptor {

	public static void main(String[] args) {

		try {
			String encryptedFileName = "encrypted.jpg";
			String decryptedFileName = "decrypted.jpg";
			String privateKeyFile = "privateKey.txt";
			// Load private keys from files
			PrivateKey privateKey = loadPrivateKey(privateKeyFile);
			// Decrypt the encrypted image file
			decryptAmdImage(encryptedFileName, decryptedFileName, privateKey);
			System.out.println("AMD image decryption successful");
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
	}

	// Method to decrypt an image file
	private static void decryptAmdImage(String inputFile, String outputFile, PrivateKey privateKey) throws Exception {
		// Read the AES key from the file
		byte[] aesKeyBytes;
		try (BufferedReader br = new BufferedReader(new FileReader("aecKey.text"))) {
			String hexString = br.readLine();
			aesKeyBytes = hexStringToBytes(hexString);
		}
		SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

		// Decrypt the image file using AES
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

		try (FileInputStream fis = new FileInputStream(inputFile);
				FileOutputStream fos = new FileOutputStream(outputFile);
				CipherInputStream cis = new CipherInputStream(fis, aesCipher)) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = cis.read(buffer)) != -1) {
				fos.write(buffer, 0, bytesRead);
			}
		}
	}

	// Method to load private key from file
	private static PrivateKey loadPrivateKey(String fileName) throws Exception {
		try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
			String encodedPrivateKey = br.readLine();
			byte[] privateKeyBytes = Base64.getDecoder().decode(encodedPrivateKey);
			java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(
					privateKeyBytes);
			java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
			return keyFactory.generatePrivate(keySpec);
		}

	}

	// Helper method to convert hexadecimal string to bytes
	private static byte[] hexStringToBytes(String hexString) {
		int len = hexString.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
					+ Character.digit(hexString.charAt(i + 1), 16));
		}
		return data;
	}
}
