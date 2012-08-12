/**
 * 
 */
package util.crypto;

import java.io.Console;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.util.Scanner;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * @author KalyanChakravarthyV
 * 
 */
public class CryptoEncDe {

	private static final String LINE_SEPERATOR = System.getProperties().getProperty("line.separator");

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		Console console = System.console();

		if (console == null) {
			System.err.println("No console defined!");
			System.exit(1);
		}

		if (args.length < 6) {
			System.out.println("Usage: java CryptoEncDe -{e|d} <file_name> -keystore <keystore_file> -k <keyname>");
			System.out.println("When -e is used, STDIN is taken for plaintext and <file_name> has encrypted contents");
			System.out.println("<keyname> is the key with which we'll have to encrypt|decrypt");
			System.exit(1);

		}

		String keyStoreFile = "";
		KeyStore keystore = KeyStore.getInstance("jceks");

		String keyName = "theKey";

		char[] storePasswordChar = new char["changeit".length()];
		"changeit".getChars(0, storePasswordChar.length, storePasswordChar, 0);

		if ("-keystore".equals(args[2])) {
			keyStoreFile = args[3];
			// Load the keystore contents
			FileInputStream fileInputStream = new FileInputStream(keyStoreFile);

			storePasswordChar = console.readPassword("[%s]", "Enter key store password");
			keystore.load(fileInputStream, storePasswordChar);
			fileInputStream.close();
		}

		if ("-k".equals(args[4])) {
			keyName = args[5];
		}

		char[] keyPasswordChar = console.readPassword("[%s]",
				"Enter key password, [press Enter if it is the same as keystore password]");

		if (keyPasswordChar.length == 0) {
			keyPasswordChar = storePasswordChar;
		}

		StringBuffer inputBuffer = new StringBuffer();

		Scanner input = new Scanner(System.in);
		do{
			inputBuffer.append(input.nextLine());
			inputBuffer.append(LINE_SEPERATOR);
		}while (input.hasNext()) ;

		System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++");
		System.out.println(inputBuffer);
		System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++");
		System.out.println();
		/*
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));

		String line = "";

		while (!(line = bufferedReader.readLine()).equalsIgnoreCase("DONE")) {
			inputBuffer.append(line);
			inputBuffer.append(LINE_SEPERATOR);

		}
		*/

		byte[] plainText = inputBuffer.toString().getBytes();
		"Haritha is Great!".getBytes("UTF-8");

		Key key = keystore.getKey(keyName, keyPasswordChar);

		// get a AES cipher object and print the provider
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");

		System.out.println("\n" + cipher.getProvider().getInfo());

		// encrypt using the key and the plaintext
		System.out.println("\nStart encryption");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(plainText);
		System.out.println("Finish encryption: ");
		byte[] encodedCipher = null;
		System.out.println(new String((encodedCipher = Base64.encode(cipherText)), "UTF-8"));

		//
		// decrypt the ciphertext using the same key
		System.out.println("\nStart decryption");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] newPlainText = cipher.doFinal(Base64.decode(encodedCipher));
		System.out.println("Finish decryption: ");

		System.out.println(new String(newPlainText, "UTF-8"));
	}

}
