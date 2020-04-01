// By turning in this file, you are asserting that the assignment is your
// orginal work and that you are complying with the stated academic misconduct
// policies for the course, the School of Computing, and the College of
// Engineering.

// https://docs.oracle.com/en/java/javase/11/security/java-security-overview1.html
// For historical (export control) reasons, the cryptography APIs are organized
// into two distinct packages:
//
// The java.security and java.security.* packages contain classes that are not
// subject to export controls (like Signature and MessageDigest)
//
// The javax.crypto package contains classes that are subject to export controls
// (like Cipher and KeyAgreement)
import java.io.Console;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.SecretKey;

import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptionTool
{
	public static void main(String[] args) throws Exception
	{
		String inFile;
		String outFile;
		String hexKey;

		// We are doing this (adding a provider) because we don't have BC installed
		// for the whole system.
		// The reason we are doing this is to see how it works. In practice you
		// might want to add a provider because your default crypto provider
		// doesn't support a cipher or cipher mode you want to use
		Security.addProvider(new BouncyCastleProvider());

		// You can test what provider is being used with getProvider().getName()
		// For simple crypto operations, the system might default to something like "SunJCE"
		System.out.println(Cipher.getInstance("AES").getProvider().getName());
		// You can force the system to use the provider you want
		System.out.println(Cipher.getInstance("AES", "BC").getProvider().getName());
		// But only for that object - it isn't a permanent state switch
		System.out.println(Cipher.getInstance("AES").getProvider().getName());
		// The system will try to use a provider that can give you what you're asking for if the default can't recognize/provide it
		System.out.println(Cipher.getInstance("AES/CBC/PKCS7Padding").getProvider().getName());
		// You can also insert a provider at a higher priority to make it the default
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		// But it only works properly if you haven't already added the provider
		System.out.println(Cipher.getInstance("AES").getProvider().getName());
		// Behold:
		Security.removeProvider("BC");
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		System.out.println(Cipher.getInstance("AES").getProvider().getName());

		if (args.length==4 && args[0].equals("-encAESCTR") && args[1].length()==64 ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(encryptAESCTR(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==4 && args[0].equals("-decAESCTR") && args[1].length()==64 ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(decryptAESCTR(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==4 && args[0].equals("-encAESCBC") && args[1].length()==64 ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(encryptAESCBC(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==4 && args[0].equals("-decAESCBC") && args[1].length()==64 ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(decryptAESCBC(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==4 && args[0].equals("-encAESGCM") && args[1].length()==64 ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(encryptAESGCM(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==4 && args[0].equals("-decAESGCM") && args[1].length()==64 ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(decryptAESGCM(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==4 && args[0].equals("-encHybridRSA") ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(encryptHybridRSA(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==4 && args[0].equals("-decHybridRSA") ) {
			hexKey = args[1];
			inFile = args[2];
			outFile = args[3];
			writeToFileWrapper(decryptHybridRSA(hexKey, readFromFileWrapper(inFile)), outFile);
		} else if (args.length==1 && args[0].equals("-genAESKey")) {
			generateAESKey();
		} else if (args.length==1 && args[0].equals("-genRSAKeyPair")) {
			generateRSAKeyPair();
		} else {
			System.out.println("This is a simple program to encrypt and decrypt files");
			System.out.println("Usage: ");
			System.out.println("    -encAESCTR <key:256 bits in as hex> <inputFile> <outputFile>  AES CTR mode encrypt");
			System.out.println("    -decAESCTR <key:256 bits in as hex> <inputFile> <outputFile>  AES CTR mode decrypt");
			System.out.println("    -encAESCBC <key:256 bits in as hex> <inputFile> <outputFile>  AES CBC mode encrypt");
			System.out.println("    -decAESCBC <key:256 bits in as hex> <inputFile> <outputFile>  AES CBC mode decrypt");
			System.out.println("    -encAESGCM <key:256 bits in as hex> <inputFile> <outputFile>  AES CBC mode encrypt");
			System.out.println("    -decAESGCM <key:256 bits in as hex> <inputFile> <outputFile>  AES CBC mode decrypt");
			System.out.println("    -encHybridRSA <public key in as hex> <inputFile> <outputFile>  encrypt with a hybrid RSA system");
			System.out.println("    -decHybridRSA <private key in as hex> <inputFile> <outputFile>  decrypt with a hybrid RSA system");
			System.out.println("    -genAESKey 	generate a 256-bit AES key");
			System.out.println("    -genRSAKeyPair 	generate a 4096-bit RSA key pair");
		}
	}

	private static byte[] readFromFileWrapper(String inFile) {
		try {
			RandomAccessFile rawDataFromFile = new RandomAccessFile(inFile, "r");
			byte[] plaintext = new byte[(int)rawDataFromFile.length()];
			rawDataFromFile.read(plaintext);
			rawDataFromFile.close();
			return plaintext;
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	private static void writeToFileWrapper(byte[] output, String outFile) {
		try {
			FileOutputStream outToFile = new FileOutputStream(outFile);
			outToFile.write(output);
			outToFile.close();
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
		}
	}

	private static byte[] encryptHybridRSA(String hexKey, byte[] plaintext) {
		try {
			// Create a public key from the hex string and set up the RSA Cipher object
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Hex.decodeHex(hexKey));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
			Cipher RSACipher = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding");
			RSACipher.init(Cipher.ENCRYPT_MODE, publicKey);

			// Generate a symmetric key to encrypt the data
			KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // We don't actually encrypt anything here, so defaulting to ECB is OK
			keyGen.init(256);
			Key AESKey = keyGen.generateKey();

			// Encrypt the symmetric AES key with the public RSA key
			byte[] encryptedKey = RSACipher.doFinal(AESKey.getEncoded());
			byte[] IVplusCipherText = encryptAESGCM(Hex.encodeHexString(AESKey.getEncoded()), plaintext);

			byte[] output = new byte[encryptedKey.length + IVplusCipherText.length];
			System.arraycopy(encryptedKey, 0, output, 0, encryptedKey.length);
			System.arraycopy(IVplusCipherText, 0, output, encryptedKey.length, IVplusCipherText.length);
			return output;
		}
		catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	public static byte[] decryptHybridRSA(String hexKey, byte[] input) {
		try {

			// Setting up with private key and for decoding
			// Create a public key from the hex string and set up the RSA Cipher object
			PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(Hex.decodeHex(hexKey));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pubKeySpec);
			Cipher RSACipher = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding");
			RSACipher.init(Cipher.DECRYPT_MODE, privateKey);

			// Creating variables to store important info
			int keySize = 512;
			byte[] encryptedKey = new byte[keySize];
			byte[] ciphertext = new byte[input.length - keySize];

			// Gettting the encrypted key
			for(int i = 0; i < keySize; i++) {
				encryptedKey[i] = input[i];
			}

			// getting the encrypted message
			for(int i = keySize; i < input.length; i++) {
				ciphertext[i - keySize] = input[i];
			}

			// Decrypting the key
			byte[] key = RSACipher.doFinal(encryptedKey);
		
			// Decrypting the message with the decrypted key and returning it
			return decryptAESGCM(Hex.encodeHexString(key),ciphertext);
		
		// If an error is thrown
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	public static byte[] decryptAESCTR(String hexKey, byte[] input) {
		try {

			// Create Array For IV And Ciphertext
			byte iv[] = new byte[16];
			byte ciphertext[] = new byte[input.length - 16];

			// Get The IV From Ciphertext
			for(int i = 0; i < 16; i++) {
				iv[i] = input[i];
			}

			// Sends in the IV
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Set up the AES key from the hex string & a Cipher object in CTR mode
			SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decodeHex(hexKey), "AES");
			Cipher encAESCTRcipher = Cipher.getInstance("AES/CTR/NoPadding");
			encAESCTRcipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

			// This Gets The Cyphertext
			for(int i = 0; i < input.length - 16; i ++) {
				ciphertext[i] = input[i+16]; 
			}

			// Decrypt The Data
			byte[] plaintext = encAESCTRcipher.doFinal(ciphertext);

			// Return Plain Text
			return plaintext;

		// If An Error Happens
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	public static byte[] decryptAESCBC(String hexKey, byte[] input) {
		try {

			// Create Array For IV And Ciphertext
			byte iv[] = new byte[16];
			byte ciphertext[] = new byte[input.length - 16];

			// Get The IV From Ciphertext
			for(int i = 0; i < 16; i++) {
				iv[i] = input[i];
			}

			// Sends in the IV
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Set up the AES key from the hex string & a Cipher object in CBC mode
			SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decodeHex(hexKey), "AES");
			Cipher encAESCBCcipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
			encAESCBCcipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

			// This Gets The Cyphertext
			for(int i = 0; i < input.length - 16; i ++) {
				ciphertext[i] = input[i+16]; 
			}

			// Decrypt The Data
			byte[] plaintext = encAESCBCcipher.doFinal(ciphertext);

			// Return Plain Text
			return plaintext;

		// If An Error Happens
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	public static byte[] decryptAESGCM(String hexKey, byte[] input) {
		try {
			
			// USED FOR 3.3 (f)
			// System.out.println(Arrays.toString(input));
			// input[16] = 0;
			// input[17] = 0;
			// input[18] = 0;

			// Create Array For IV And Ciphertext
			byte iv[] = new byte[16];
			byte ciphertext[] = new byte[input.length - 16];

			// Get The IV From Ciphertext
			for(int i = 0; i < 16; i++) {
				iv[i] = input[i];
			}

			// Sends in the IV
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Set up the AES key from the hex string & a Cipher object in GCM mode
			SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decodeHex(hexKey), "AES");
			Cipher encAESGCMcipher = Cipher.getInstance("AES/GCM/NoPadding");
			encAESGCMcipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

			// This Gets The Cyphertext
			for(int i = 0; i < input.length - 16; i ++) {
				ciphertext[i] = input[i+16]; 
			}

			// Decrypt the data
			byte[] plaintext = encAESGCMcipher.doFinal(ciphertext);

			// Return Plain Text
			return plaintext;

		// If An Error Happens
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	private static void generateAESKey() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // We don't actually encrypt anything here, so defaulting to ECB is OK
			keyGen.init(256);
			System.out.println("Here is a hex string encoding of some bytes you can use as an AES key: " + Hex.encodeHexString(keyGen.generateKey().getEncoded()));
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
		}
	}

	private static void generateRSAKeyPair() {
		try {
			KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA");
			keyPair.initialize(4096);

			KeyPair kp = keyPair.generateKeyPair();
			System.out.println("Here is a hex string encoding of the RSA public key: " + Hex.encodeHexString(kp.getPublic().getEncoded()));
			System.out.println("Here is a hex string encoding of the RSA private key: " + Hex.encodeHexString(kp.getPrivate().getEncoded()));
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
		}
	}

	private static byte[] encryptAESCTR(String hexKey, byte[] plaintext) {
		try {
			// Generate a random IV
			SecureRandom random = new SecureRandom();
			byte iv[] = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Set up the AES key from the hex string & a Cipher object in CTR mode
			SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decodeHex(hexKey), "AES");
			Cipher encAESCTRcipher = Cipher.getInstance("AES/CTR/NoPadding");
			encAESCTRcipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

			// Encrypt the data
			byte[] ciphertext = encAESCTRcipher.doFinal(plaintext);

			byte[] output = new byte[iv.length + ciphertext.length];
			// System.out.println("CTR: " + output.length);
			System.arraycopy(iv, 0, output, 0, iv.length);
			System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);
			return output;
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	private static byte[] encryptAESCBC(String hexKey, byte[] plaintext) {
		try {
			// Generate a random IV
			SecureRandom random = new SecureRandom();
			byte iv[] = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Set up the AES key from the hex string & a Cipher object in CBC mode
			SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decodeHex(hexKey), "AES");
			Cipher encAESCBCcipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
			encAESCBCcipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

			// Encrypt the data
			byte[] ciphertext = encAESCBCcipher.doFinal(plaintext);

			byte[] output = new byte[iv.length + ciphertext.length];
			// System.out.println("CBC: " + output.length);
			System.arraycopy(iv, 0, output, 0, iv.length);
			System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);
			return output;
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	private static byte[] encryptAESGCM(String hexKey, byte[] plaintext) {
		try {
			// Generate a random IV
			SecureRandom random = new SecureRandom();
			byte iv[] = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Set up the AES key from the hex string & a Cipher object in GCM mode
			SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decodeHex(hexKey), "AES");
			Cipher encAESGCMcipher = Cipher.getInstance("AES/GCM/NoPadding");
			encAESGCMcipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

			// Encrypt the data
			byte[] ciphertext = encAESGCMcipher.doFinal(plaintext);

			byte[] output = new byte[iv.length + ciphertext.length];
			// System.out.println("GCM: " + output.length);
			System.arraycopy(iv, 0, output, 0, iv.length);
			System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);
			return output;
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}
}
