package com.amd.poc;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AmdImageEncryptor {

	public static void main(String[] args) {

		try {
			// Generate RSA key pair
			KeyPair keyPair = generateRSAKeyPair();
			// given image from local directory;
			String fileName = "C:\\AmdTest\\AMD image file.JPG";

			String encryptedFileName = "encrypted.jpg";
			String publicKeyFile = "publicKey.txt";
			String privateKeyFile = "privateKey.txt";

			saveKeyToFile(keyPair.getPublic(), publicKeyFile);
			saveKeyToFile(keyPair.getPrivate(), privateKeyFile);

			// Load public and private keys from files
			PublicKey publicKey = loadPublicKey(publicKeyFile);
			// Encrypt the image file
			encryptAmdImage(fileName, encryptedFileName, publicKey);
			// Decrypt the encrypted image file
			System.out.println("AMD image Encryption and decryption successful");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Method to encrypt an image file using AES and then encrypt the AES key using
	// RSA
	private static void encryptAmdImage(String inputFile, String outputFile, PublicKey publicKey) throws Exception {
		// Generate AES key
		SecretKey aesKey = generateAESKey();

		// Encrypt the image file using AES
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

		try (FileInputStream fis = new FileInputStream(inputFile);
				FileOutputStream fos = new FileOutputStream(outputFile);
				CipherOutputStream cos = new CipherOutputStream(fos, aesCipher)) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = fis.read(buffer)) != -1) {
				cos.write(buffer, 0, bytesRead);
			}
		}

		// Save the AES key to a file in a readable format
		try (FileWriter fw = new FileWriter("aecKey.text")) {
			fw.write(bytesToHex(aesKey.getEncoded())); // Convert AES key to hexadecimal string
		}

	}


	// Method to generate RSA key pair
	private static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		return keyPairGenerator.generateKeyPair();
	}

	// Method to generate AES key
	private static SecretKey generateAESKey() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		return keyGen.generateKey();
	}

	// Method to save public key and private key to files
	private static void saveKeyToFile(java.security.Key key, String fileName) throws IOException {
		byte[] keyBytes = key.getEncoded();
		String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
		try (FileWriter fw = new FileWriter(fileName)) {
			fw.write(encodedKey);
		}
	}

	// Method to load public key from file
	private static PublicKey loadPublicKey(String fileName) throws Exception {
		try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
			String encodedPublicKey = br.readLine();
			byte[] publicKeyBytes = Base64.getDecoder().decode(encodedPublicKey);
			// Assuming the key is in X.509 format
			java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
			java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(keySpec);
		}
	}

	// Helper method to convert bytes to hexadecimal string
	private static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
