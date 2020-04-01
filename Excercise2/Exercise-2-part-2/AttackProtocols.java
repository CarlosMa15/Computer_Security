// By turning in this file, you are asserting that the assignment is your
// orginal work and that you are complying with the stated academic misconduct
// policies for the course, the School of Computing, and the College of
// Engineering.

//Remove
import java.util.Arrays;
import java.security.Provider;

import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.io.InputStream;
import java.io.OutputStream;

import java.net.ServerSocket;
import java.net.Socket;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import java.security.Key;
import java.security.Security;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import java.math.BigInteger;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AttackProtocols {
  static String serverIP = "50.116.14.202";

  static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
  static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");

  public static void main(String[] args) throws Exception {
    String inFile;
    String outFile;
    String portNum;

    Security.insertProviderAt(new BouncyCastleProvider(), 1);

    if (args.length==4 && args[0].equals("-attackA")) {
      portNum = args[1];
      inFile = args[2];
      outFile = args[3];
      writeToFileWrapper(attackA(portNum, readFromFileWrapper(inFile)), outFile);
    } else if (args.length==3 && args[0].equals("-attackB")) {
      portNum = args[1];
      outFile = args[2];
      writeToFileWrapper(attackB(portNum), outFile);
    } else {
      System.out.println("Usage: ");
      System.out.println("    -attackA <server port #> <raw wireshark capture file> <decrypted secret value destination file>");
      System.out.println("    -attackB <server port #> <decrypted secret value destination file>");
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

  private static void writeToFileWrapper(byte[] output, String outFile) {
    try {
      FileOutputStream outToFile = new FileOutputStream(outFile);
      outToFile.write(output);
      outToFile.close();
    } catch (Exception e) {
      System.out.println("Oh no! " + e);
    }
  }

  private static byte[] attackA(String portNum, byte[] input) {

    try {

      // The message from the client to the server
      final byte[] message1 = new byte[64];

      // The message from the server to the client
      final byte[] message2 = new byte[185];

      // Extracting message 1
      System.arraycopy(input, 0, message1, 0, 64);

      // Extracting message 2
      System.arraycopy(input, 64, message2, 0, 185);

      // The IV from the message 1
      final byte[] clientIV = new byte[16];

      // Extracting the IV from message 1
      System.arraycopy(message1, 0, clientIV, 0, 16);

      // The nonce or our session key
      final byte[] sessionKey = new byte[32];

      // Extracting the session key
      System.arraycopy(message2, 0, sessionKey, 0, 32);

      // The encrypted nonce or session key
      final byte[] encrytpedSessionKey = new byte[64];

      // adding the IV to the encrypted nonce or session key
      System.arraycopy(clientIV, 0, encrytpedSessionKey, 0, 16);

      // adding the encrypted nonce or session key
      System.arraycopy(message2, 32, encrytpedSessionKey, 16, 48);

      // The encrypted message from the server to the client
      final byte[] encrytpedMessage = new byte[89];

      // Extracting the encrypted secret value
      System.arraycopy(message2, 96, encrytpedMessage, 0, 89);

      // System.out.println("Connecting to " + portNum + " on port 11337");
      final Socket socket = new Socket("50.116.14.202", Integer.parseInt(portNum));
      final InputStream inputStream = socket.getInputStream();
      final OutputStream outputStream = socket.getOutputStream();
      outputStream.write( encrytpedSessionKey); //message1); // b
      outputStream.flush();
      // System.out.println("\tMessage 1 sent to server.");
      final byte[] b2 = new byte[185];
      inputStream.read(b2);
      // System.out.println("\tMessage 2 received from server.");
      final byte[] iv = new byte[16];
      System.arraycopy(b2, 80, iv, 0, 16);
      final byte[] input2 = new byte[89];
      System.arraycopy(b2, 96, input2, 0, 89);
      final IvParameterSpec params = new IvParameterSpec(iv);
      final Cipher instance3 = Cipher.getInstance("AES/GCM/NoPadding");
      instance3.init(2, new SecretKeySpec(sessionKey, "AES"), params);
      // System.out.println("\tSecret value successfully decrypted.");
      socket.close();
      return instance3.doFinal(input2);

    } catch (Exception obj) {
      return "Error Happened :-(".getBytes();
    }

  }

  private static byte[] attackB(String portNum) {

    try {

      System.out.println("Launching server...");
      // Listen for connections for the client
      ServerSocket listener = new ServerSocket(Integer.parseInt(portNum));
      System.out.println("Listening for connections on port " + portNum);

      // For each connection spin off a new protocol instance.
      Socket connection = listener.accept();

      Socket socket;
      DataOutputStream out;
			DataInputStream in;
      
      socket = connection;

      System.out.println("\nStarting protocol instance...");
      out = new DataOutputStream(socket.getOutputStream());
      in = new DataInputStream(socket.getInputStream());

      Security.insertProviderAt(new BouncyCastleProvider(), 1);

      // Reading Message from Client
      byte[] message1 = new byte[in.readInt()];
      in.read(message1);
      System.out.println("Read Message from Client");

      // Sending New Message to Server
      System.out.println("Connecting to 50.116.14.202 on port 11338");
      final Socket socket1 = new Socket("50.116.14.202", Integer.parseInt(portNum));
      final DataInputStream dataInputStream = new DataInputStream(socket1.getInputStream());
      final DataOutputStream dataOutputStream = new DataOutputStream(socket1.getOutputStream());
      Security.insertProviderAt((Provider)new BouncyCastleProvider(), 1);
      final DHParameterSpec params = new DHParameterSpec(AttackProtocols.p, AttackProtocols.g);
      final KeyPairGenerator instance = KeyPairGenerator.getInstance("DiffieHellman");
      instance.initialize(params);
      final KeyPair generateKeyPair = instance.generateKeyPair();
      final PrivateKey private1 = generateKeyPair.getPrivate();
      final PublicKey public1 = generateKeyPair.getPublic();
      dataOutputStream.writeInt(public1.getEncoded().length);
      dataOutputStream.write(public1.getEncoded());
      dataOutputStream.flush();

      // Reading message from Server
      final byte[] array2 = new byte[dataInputStream.readInt()];
      dataInputStream.read(array2);
      System.out.println("Reading message from server");//Arrays.toString(array2));

      // Write message to client
      out.writeInt(array2.length);
			out.write(array2);
			out.flush();

      // Reading message from client
      byte[] message3 = new byte[512];
			in.read(message3);
      System.out.println("Read message from client");//Arrays.toString(message3));

      // Right message to server
      dataOutputStream.write(message3);
      dataOutputStream.flush();
      System.out.println("Right message to server");

      // Read message from server
      final byte[] b = new byte[601];
      dataInputStream.read(b);
      System.out.println("Read message from server");

      final byte[] array3 = new byte[512];
      System.arraycopy(b, 0, array3, 0, 512);
      final Key calculateSessionKeyUsingDH = calculateSessionKeyUsingDH(KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(array2)), private1, 32);
      final byte[] iv = new byte[16];
      System.arraycopy(b, 512, iv, 0, 16);
      final IvParameterSpec params2 = new IvParameterSpec(iv);
      final Cipher instance2 = Cipher.getInstance("AES/GCM/NoPadding");
      instance2.init(2, calculateSessionKeyUsingDH, params2);
      final byte[] input = new byte[73];
      System.arraycopy(b, 528, input, 0, 73);
      System.out.println("Secret value successfully decrypted.");
      listener.close();
      socket.close();
      socket1.close();
      return instance2.doFinal(input);

    } catch(Exception e) {
			System.out.println("Oh no! " + e);
      return "Not yet implemented.".getBytes();
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
