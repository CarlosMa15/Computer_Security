// Implements the server side of:
//
// C -> S: g^x mod p
// S -> C: g^y mod p
// C -> S: SignC(g^y mod p)
// S -> C: SignS(g^x mod p) || E(g^xy mod p, SecretValue2)

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.RandomAccessFile;

import java.math.BigInteger;

import java.net.ServerSocket;
import java.net.Socket;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProtocolBServer {

	// Diffie-Hellman g and p values
	//
	// OKish to hardcode in if p is big enough, but a problem if a bunch of servers
	// use the same g and p (because, as described in lecture, that means it
	// becomes worth it to pre-compute and store g^x mod p for a lot of values of
	// x in a lookup table)
	static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");

	static String portNum;
	static String clientPubKey;
	static String serverPrivKey;
	static String secretValue;

	public static void main(String[] args) {
		if (args.length==4) {
			try {
				portNum = args[0];
				clientPubKey = new String(readFromFileWrapper(args[1]));
				serverPrivKey = new String(readFromFileWrapper(args[2]));
				secretValue = new String(readFromFileWrapper(args[3]));

				System.out.println("Launching server...");
				// Listen for connections for the client
				ServerSocket listener = new ServerSocket(Integer.parseInt(portNum));
				ThreadPoolExecutor threadPool = (ThreadPoolExecutor) Executors.newCachedThreadPool();
				System.out.println("Listening for connections on port " + portNum);
				while (true) {
					// For each connection spin off a new protocol instance.
					Socket connection = listener.accept();
					threadPool.execute(new ProtocolInstance(connection));
				}
			} catch(Exception e) {
				System.out.println("Oh no! " + e);
			}
		} else {
			System.out.println("Usage: ");
			System.out.println("\t<port> <client pub file> <server priv file> <secret value file>");
		}
	}

	private static byte[] readFromFileWrapper(String inFile) {
		try {
			RandomAccessFile rawDataFromFile = new RandomAccessFile(inFile, "r");
			byte[] contents = new byte[(int)rawDataFromFile.length()];
			rawDataFromFile.read(contents);
			rawDataFromFile.close();
			return contents;
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	// Implements one instance of the protocol
	private static class ProtocolInstance implements Runnable {
		Socket socket;
		PrivateKey y;
		PublicKey gToTheY;
		PublicKey gToTheX;
		Key aesSessionKey;

		public ProtocolInstance(Socket connection) {
			this.socket = connection;
		}

		public void run() {
			DataOutputStream out;
			DataInputStream in;

			try {
				System.out.println("\n\tStarting protocol instance...");
				out = new DataOutputStream(socket.getOutputStream());
				in = new DataInputStream(socket.getInputStream());

				Security.insertProviderAt(new BouncyCastleProvider(), 1);

				byte[] message1 = new byte[in.readInt()];
				in.read(message1);

				setRandomYandCalculateGToTheY();

				out.writeInt(gToTheY.getEncoded().length);
				out.write(gToTheY.getEncoded());
				out.flush();

				byte[] message3 = new byte[512];
				in.read(message3);

				if(signatureIsValid(Hex.decodeHex(clientPubKey), gToTheY.getEncoded(), message3)) {
					System.out.println("\t\tClient signature valid.");
					byte[] message4 = new byte[601];

					System.arraycopy(signMessage(Hex.decodeHex(serverPrivKey), message1), 0, message4, 0, 512);

					X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
					KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
					gToTheX = keyfactoryDH.generatePublic(x509Spec);
					aesSessionKey = calculateSessionKeyUsingDH(gToTheX, y, 32);

					SecureRandom random = new SecureRandom();
					byte iv[] = new byte[16];
					random.nextBytes(iv);
					IvParameterSpec ivSpec = new IvParameterSpec(iv);
					Cipher encAESsessionCipher = Cipher.getInstance("AES/GCM/NoPadding");
					encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey, ivSpec);
					byte[] ciphertext = encAESsessionCipher.doFinal(secretValue.getBytes());

					System.arraycopy(iv, 0, message4, 512, 16);
					System.arraycopy(ciphertext, 0, message4, 528, 73);

					out.write(message4);
					out.flush();
					System.out.println("\t\tSecret value sent.");
				} else {
					System.out.println("\t\tServer signature not valid! Attack detected.");
				}
				socket.close();
				System.out.println("\tConnection closed.");
			} catch (Exception e) {
				System.out.println("Oh no! " + e);
			}
		}

		private void setRandomYandCalculateGToTheY() {
			try {
				DHParameterSpec dhSpec = new DHParameterSpec(p, g);
				KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
				diffieHellmanGen.initialize(dhSpec);
				KeyPair serverPair = diffieHellmanGen.generateKeyPair();
				y = serverPair.getPrivate();
				gToTheY = serverPair.getPublic();
			} catch (Exception e) {
				System.out.println("Oh no! " + e);
			}
		}
	}

	private static Key calculateSessionKeyUsingDH(PublicKey receivedValue, PrivateKey secretExponent, int keyLength) {
		try {
			KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
			keyAgree.init(secretExponent);
			keyAgree.doPhase(receivedValue, true);
			byte[] dhCalculationResult = keyAgree.generateSecret();
			byte[] selectedBytesForSessionKey = new byte[keyLength];
			System.arraycopy(dhCalculationResult, 0, selectedBytesForSessionKey, 0, keyLength);
			Key key = new SecretKeySpec(selectedBytesForSessionKey, "AES");
			return key;
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}

	private static boolean signatureIsValid(byte[] encodedPublicKey, byte[] content, byte[] signatureToVerify) {
		try {
			// Obviously client and server need to know what algorithms they're using for
			// signing so that they can use the same ones (but it's not a big secret
			// from the attacker)
			Signature verifyObject = Signature.getInstance("SHA3-512withRSA");
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey pubRSAKey = kf.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
			verifyObject.initVerify(pubRSAKey);
			verifyObject.update(content);
			return verifyObject.verify(signatureToVerify);
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return false;
		}
	}

	private static byte[] signMessage(byte[] encodedPrivKey, byte[] message) {
		try {
			// Obviously client and server need to know what algorithms they're using for
			// signing so that they can use the same ones (but it's not a big secret
			// from the attacker)
			Signature signObject = Signature.getInstance("SHA3-512withRSA");
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey privRSAKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivKey));
			signObject.initSign(privRSAKey);
			signObject.update(message);
			return signObject.sign();
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
			return null;
		}
	}
}
