// By turning in this file, you are asserting that the assignment is your
// orginal work and that you are complying with the stated academic misconduct
// policies for the course, the School of Computing, and the College of
// Engineering.

import java.io.Console;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;

import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;

public class AlterCTREncryptedFileWithoutKey
{
  public static void main(String[] args) throws Exception
  {
    String originalPlaintextFile;
    String targetPlaintextFile;
    String dataToAlterFile;
    String alteredCiphertextDestinationFile;

    if (args.length==4) {

/******************************************************************************************************************************************************************
javac -classpath "./*" EncryptionTool.java 
java -classpath "./*":. EncryptionTool -encAESCTR 67cd21b35eced6d3268c9fc47f512ad5436ca1843ab08988810ff7f3a3f4bb05 original-salary-plaintext originalEncryptedFile
javac -classpath "./*" AlterCTREncryptedFileWithoutKey.java
java -classpath "./*":. AlterCTREncryptedFileWithoutKey original-salary-plaintext target-salary-plaintext originalEncryptedFile targetEncryptedFile
java -classpath "./*":. EncryptionTool -decAESCTR 67cd21b35eced6d3268c9fc47f512ad5436ca1843ab08988810ff7f3a3f4bb05 targetEncryptedFile targetFile
******************************************************************************************************************************************************************/

      // Getting the arguments passed
      originalPlaintextFile = args[0];
      targetPlaintextFile = args[1];
      dataToAlterFile = args[2];
      alteredCiphertextDestinationFile = args[3];

      // Getting M
      byte[] message = readFromFileWrapper(originalPlaintextFile);

      // Getting M'
      byte[] messagePrime = readFromFileWrapper(targetPlaintextFile);

      // iv + ciphertext
      byte[] IVciphertext = readFromFileWrapper(dataToAlterFile);

      // Used to store the cipertext C or (K orx M)
      byte[] ciphertext = new byte[IVciphertext.length - 16];

      // Temp variable to store calculation results
      byte[] result = new byte[message.length];

      // The variable that will store the final result (iv + ciphertext)
      byte[] finalResult = new byte[IVciphertext.length];

      // storing the same iv in the final result
      for(int i = 0; i < 16; i++) {
        finalResult[i] = IVciphertext[i];
      }

      // Getting the ciphertext
      for(int i = 0; i < (IVciphertext.length - 16); i++)
        ciphertext[i] = IVciphertext[i+16];

      // result = (C xor M') or ((M xor K) xor M')
      int i = 0;
      for (byte b : ciphertext)
        result[i] = (byte) (b ^ messagePrime[i++]);

      // result = (C xor M' xor M) or ((M xor K) xor M' xor M)
      // ((M xor K) xor M' xor M), the 2 M should cancel each other
      // result = K xor M' which is what we wanted
      i = 0;
      for (byte b : message)
        result[i] = (byte)(b ^ result[i++]);

      // final result = iv + (K xor M')
      for(int j = 0; j < (IVciphertext.length - 16); j++)
        finalResult[j+16] = result[j];

      // write the new encrypted file
      writeToFileWrapper(finalResult, alteredCiphertextDestinationFile);

    } else {
      System.out.println("Usage: ");
      System.out.println("The first argument should be the original plaintext file.");
      System.out.println("The second argument should be the desired plaintext to which the altered ciphertext will decrypt. The files must be the same size.");
      System.out.println("The third argument should be the original encrypted file.");
      System.out.println("The fourth argument should be the file to which the altered encrypted file will be written.");
    }
  }

  /***********************************************************
  File reader provided by the Assignment, returns byte[]
  ***********************************************************/
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

  /***********************************************************
  File writer provided by the Assignment, creates file
  ***********************************************************/
	private static void writeToFileWrapper(byte[] output, String outFile) {
		try {
			FileOutputStream outToFile = new FileOutputStream(outFile);
			outToFile.write(output);
			outToFile.close();
		} catch (Exception e) {
			System.out.println("Oh no! " + e);
		}
	}
}