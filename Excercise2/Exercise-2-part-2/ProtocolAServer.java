// DO NOT DISTRIBUTE

// Implements the server side of:
//
// C -> S: E(Kcs1, SessionKey)
// S -> C: nonce||E(Kcs1, nonce)||E(SessionKey, SecretValue1)

import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;

import java.net.ServerSocket;
import java.net.Socket;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProtocolAServer {

  static String portNum;
  static String key;
  static String secretValue;

  public static void main(String[] args) throws Exception {
    if (args.length==3) {
      try {
        portNum = args[0];
        key = new String(readFromFileWrapper(args[1]));
				secretValue = new String(readFromFileWrapper(args[2]));

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
      System.out.println("\t<port> <key file> <secret value file>");
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

  private static class ProtocolInstance implements Runnable {
    Socket socket;

    public ProtocolInstance(Socket connection) {
      this.socket = connection;
    }

    public void run() {
      OutputStream out;
      InputStream in;

      try {
        System.out.println("\n\tStarting protocol instance...");
        out = socket.getOutputStream();
        in = socket.getInputStream();

        byte[] message1 = new byte[64];
        in.read(message1);

        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        Key Kcs1 = new SecretKeySpec(Hex.decodeHex(key), "AES");

        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[48];
        System.arraycopy(message1, 0, iv, 0, 16);
        System.arraycopy(message1, 16, ciphertext, 0, 48);

        // initialize AES cipher object
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher Kcs1CipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
        Kcs1CipherDecrypt.init(Cipher.DECRYPT_MODE, Kcs1, ivSpec);

        byte[] sessionKeyBytes = Kcs1CipherDecrypt.doFinal(ciphertext);
        System.out.print("\t\tSession key decrypted.");

        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);

        Cipher Kcs1CipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
        Kcs1CipherEncrypt.init(Cipher.ENCRYPT_MODE, Kcs1, ivSpec);
        byte[] nonceCiphertext = Kcs1CipherEncrypt.doFinal(nonce);

        byte[] iv2 = new byte[16];
        random.nextBytes(iv2);
        IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
        Cipher SessionKeyCipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
        Key sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
        SessionKeyCipherEncrypt.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec2);
        byte[] secretValueCipherText = SessionKeyCipherEncrypt.doFinal(secretValue.getBytes());

        byte[] message2 = new byte[185];
        System.arraycopy(nonce, 0, message2, 0, 32);
        System.arraycopy(nonceCiphertext, 0, message2, 32, 48);
        System.arraycopy(iv2, 0, message2, 80, 16);
        System.arraycopy(secretValueCipherText, 0, message2, 96, 89);
        out.write(message2);
        out.flush();
        socket.close();
        System.out.println("\tConnection closed.");
      } catch (Exception e) {
        System.out.println("Oh no! " + e);
        return;
      }
    }
  }
}
