package com.amd.poc;

import java.io.FileInputStream;
import java.security.MessageDigest;

public class FileHashGenerator {

	public static void main(String[] args) throws Exception {
		String amdFile = "C:\\AmdTest\\AMD image file.JPG";
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		FileInputStream fileInput = new FileInputStream(amdFile);
		byte[] buffer = new byte[1024];
		int bytes;
		while ((bytes = fileInput.read(buffer)) != -1) {
			digest.update(buffer, 0, bytes);
		}
		fileInput.close();
		byte[] hash = digest.digest();
		StringBuilder hexString = new StringBuilder();
		for (byte b : hash) {
			String hex = Integer.toHexString(0xff & b);
			if (hex.length() == 1)
				hexString.append('0');
			hexString.append(hex);
		}
		System.out.println("SHA-256 Hash of " + amdFile + ": " + hexString.toString());
	}

}
