/**
 * 
 */
package util.crypto;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * @author KalyanChakravarthyV
 * 
 */
public class CryptoEncDe {

	private static KeyStore keystore = null;
	private static boolean intialized = false;

	public CryptoEncDe() {

	}

	private static final String LINE_SEPERATOR = System.getProperties().getProperty("line.separator");

	/**
	 * @param args
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */

	public void init(String keyStoreType, File keyStoreFile, char[] storePassword) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {

		keystore = KeyStore.getInstance("jceks");
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream fileInputStream = new FileInputStream(keyStoreFile);
		keystore.load(fileInputStream, storePassword);
		fileInputStream.close();
		intialized = true;
	}

	public byte[] encrypt(String keyName, char[] keyPassword, String plainText) throws IllegalBlockSizeException,
			BadPaddingException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
		if (!intialized)
			throw new IllegalStateException(
					"Keystore not initialized, init(String, File, char[]) method not invoked yet");

		Key key = keystore.getKey(keyName, keyPassword);

		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		return cipher.doFinal(plainText.getBytes());
	}

	public byte[] decrypt(String keyName, char[] keyPassword, byte[] encodedCipher) throws UnrecoverableKeyException,
			KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (!intialized)
			throw new IllegalStateException(
					"Keystore not initialized, init(String, File, char[]) method not invoked yet");

		Key key = keystore.getKey(keyName, keyPassword);

		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");

		cipher.init(Cipher.DECRYPT_MODE, key);

		return cipher.doFinal(encodedCipher);
	}

	public static void main(String[] args) throws Exception {

		Console console = System.console();

		CryptoEncDe cryptoEncDe = new CryptoEncDe();

		if (console == null) {
			System.err.println("No console defined!");
			System.exit(1);
		}
		// java -cp bin;lib\bcprov-ext-jdk16-146.jar; util.crypto.CryptoEncDe -e
		// keys.txt -keystore keystore.jck -key TheKey
		if (args.length < 6) {
			System.out.println("Usage: java CryptoEncDe -{e|d} <file_name> -keystore <keystore_file> -k <keyname>");
			System.out.println("When -e is used, STDIN is taken for plaintext and <file_name> has encrypted contents");
			System.out.println("<keyname> is the key with which we'll have to encrypt|decrypt");
			System.exit(1);

		}

		String keyStoreFile = "";

		String keyName = "theKey";

		char[] storePasswordChar = "changeit".toCharArray();


		if ("-keystore".equals(args[2])) {
			keyStoreFile = args[3];
			storePasswordChar = console.readPassword("[%s]", "Enter key store password");
		}

		if ("-k".equals(args[4])) {
			keyName = args[5];
		}

		char[] keyPasswordChar = console.readPassword("[%s]",
				"Enter key password, [press Enter if it is the same as keystore password]");

		if (keyPasswordChar == null || keyPasswordChar.length == 0) {
			keyPasswordChar = storePasswordChar;
		}

		cryptoEncDe.init("jceks", new File(keyStoreFile), storePasswordChar);

		StringBuffer inputBuffer = new StringBuffer();

		String line = "";

		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));

		while ((line = bufferedReader.readLine()) != null) {
			inputBuffer.append(line);
			inputBuffer.append(LINE_SEPERATOR);
		}

		System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++");
		System.out.print(inputBuffer);
		System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++");
		System.out.println();

		byte[] encodedCipher = null;
		System.out.println(new String(encodedCipher = Base64.encode(cryptoEncDe.encrypt(keyName, keyPasswordChar,
				inputBuffer.toString().trim())), "UTF-8"));

		System.out.println(new String(cryptoEncDe.decrypt(keyName, keyPasswordChar, Base64.decode(encodedCipher)),
				"UTF-8"));

	}
}