// By turning in this file, you are asserting that the assignment is your
// orginal work and that you are complying with the stated academic misconduct
// policies for the course, the School of Computing, and the College of
// Engineering.

// Implements the client side of:
//
// C -> S: g^x mod p
// S -> C: g^y mod p
// C -> S: SignC(g^y mod p)
// S -> C: SignS(g^x mod p) || E(g^xy mod p, SecretValue2)

// (1) Takes in port number instead of hardcoding it
// (2) Uses keystore instead of hardcoded keys

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;

import java.math.BigInteger;

import java.net.Socket;
import java.security.Provider;
import java.security.Key;
import java.security.KeyStore;
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
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProtocolBClientUsingKeyStore {

	// Diffie-Hellman g and p values
	//
	// OKish to hardcode in if p is big enough, but a problem if a bunch of servers
	// use the same g and p (because, as described in lecture, that means it
	// becomes worth it to pre-compute and store g^x mod p for a lot of values of
	// x in a lookup table)
	static final BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static final BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");

	static final String serverIP = "50.116.14.202";

	static PrivateKey x;
	static PublicKey gToTheY;
	static PublicKey gToTheX;
	static Key aesSessionKey;
	static KeyStore ks;
	static String keystoreFile;
	static String keystorePass;
	static String portNum;
	static String outputFile;

	public static void main(String[] args) {
		if (args.length==4) {
			portNum = args[0];
			keystoreFile = args[1];
			keystorePass = args[2];
			outputFile = args[3];
			startProtocol();
		} else {
			System.out.println("Usage: ");
			System.out.println("    <server port #> <keystore file> <keystore password> <decrypted secret value destination file>");
		}
	}

	private static void startProtocol() {

		try (FileInputStream fis = new FileInputStream(keystoreFile)) {
			ks = KeyStore.getInstance("pkcs12");
			ks.load(fis, keystorePass.toCharArray());

			Certificate serverCertificate = ks.getCertificate​("server");
			Certificate clientCertificate = ks.getCertificate​("client");
			PrivateKey clientPrivateKey = (PrivateKey)ks.getKey​("client", keystorePass.toCharArray());
			PublicKey serverPublicKey = serverCertificate.getPublicKey();
			PublicKey clientPublicKey = clientCertificate.getPublicKey();

			System.out.println(clientPrivateKey);
			System.out.println(serverPublicKey);
			System.out.println(clientPublicKey);


			System.out.println("Connecting to 50.116.14.202 on port 11338");
            final Socket socket = new Socket("50.116.14.202", Integer.parseInt(portNum));
            final DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            final DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            Security.insertProviderAt((Provider)new BouncyCastleProvider(), 1);
            final DHParameterSpec params = new DHParameterSpec(ProtocolBClientUsingKeyStore.p, ProtocolBClientUsingKeyStore.g);
            final KeyPairGenerator instance = KeyPairGenerator.getInstance("DiffieHellman");
            instance.initialize(params);
            final KeyPair generateKeyPair = instance.generateKeyPair();
            final PrivateKey private1 = generateKeyPair.getPrivate();
            final PublicKey public1 = generateKeyPair.getPublic();
            dataOutputStream.writeInt(public1.getEncoded().length);
            dataOutputStream.write(public1.getEncoded());
            dataOutputStream.flush();

			System.out.println("Right");
            
            final byte[] array2 = new byte[dataInputStream.readInt()];
            dataInputStream.read(array2);

			System.out.println("Read");

            dataOutputStream.write(signMessage(clientPrivateKey.getEncoded(), array2));
            dataOutputStream.flush();

			System.out.println("wRight");

            final byte[] b = new byte[601];
            dataInputStream.read(b);
            
            final byte[] array3 = new byte[512];
            System.arraycopy(b, 0, array3, 0, 512);
            if (signatureIsValid(serverPublicKey.getEncoded(), public1.getEncoded(), array3)) {
                System.out.println("\tServer signature valid.");
                final Key calculateSessionKeyUsingDH = calculateSessionKeyUsingDH(KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(array2)), private1, 32);
                final byte[] iv = new byte[16];
                System.arraycopy(b, 512, iv, 0, 16);
                final IvParameterSpec params2 = new IvParameterSpec(iv);
                final Cipher instance2 = Cipher.getInstance("AES/GCM/NoPadding");
                instance2.init(2, calculateSessionKeyUsingDH, params2);
                final byte[] input = new byte[73];
                System.arraycopy(b, 528, input, 0, 73);
				System.out.println("\tSecret value successfully decrypted.");
                instance2.doFinal(input);
				writeToFileWrapper(instance2.doFinal(input),outputFile);
            }
            else {
                // System.out.println("\tServer signature not valid! Attack detected.");
				writeToFileWrapper(getBadSignatureErrorString(), outputFile);
            }
            socket.close();
            System.out.println("Connection closed.");

		} catch (Exception e) {
			System.out.println("Oh no! " + e);
		}

		System.out.println("Not yet implemented.");
	}

	// If the signature from the server is not valid, print this to file instead
	// of the decrypted value
	private static byte[] getBadSignatureErrorString() {
		return "Server signature not valid! Attack detected.".getBytes();
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

	    private static byte[] signMessage(final byte[] encodedKey, final byte[] data) {
			try {
				final Signature instance = Signature.getInstance("SHA3-512withRSA");
				instance.initSign(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encodedKey)));
				instance.update(data);
				return instance.sign();
			}
			catch (Exception obj) {
				System.out.println("Oh no! " + obj);
				return null;
			}
		}

    private static boolean signatureIsValid(final byte[] encodedKey, final byte[] data, final byte[] signature) {
        try {
            final Signature instance = Signature.getInstance("SHA3-512withRSA");
            instance.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedKey)));
            instance.update(data);
            return instance.verify(signature);
        }
        catch (Exception obj) {
            System.out.println("Oh no! " + obj);
            return false;
        }
    }

    private static Key calculateSessionKeyUsingDH(final PublicKey key, final PrivateKey key2, final int n) {
        try {
            final KeyAgreement instance = KeyAgreement.getInstance("DiffieHellman");
            instance.init(key2);
            instance.doPhase(key, true);
            final byte[] generateSecret = instance.generateSecret();
            final byte[] key3 = new byte[n];
            System.arraycopy(generateSecret, 0, key3, 0, n);
            return new SecretKeySpec(key3, "AES");
        }
        catch (Exception obj) {
            System.out.println("Oh no! " + obj);
            return null;
        }
    }
}
