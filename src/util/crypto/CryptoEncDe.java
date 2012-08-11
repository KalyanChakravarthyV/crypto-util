/**
 * 
 */
package util.crypto;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.util.encoders.Base64;

/**
 * @author KalyanChakravarthyV
 * 
 */
public class CryptoEncDe {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		
		if(args.length < 6){
			System.out.println("Usage: java CryptoEncDe -{e|d} <file_name> -keystore <keystore_file> -k <keyname>");
			System.out.println("When -e is used, STDIN is taken for plaintext and <file_name> has encrypted contents");
			System.out.println("<keyname> is the key with which we'll have to encrypt|decrypt");
		}

		if("-keystore".equals(args[2])){
			
		}
		
		// check args and get plaintext
		if (args.length != 1) {
			System.err.println("Usage: java PrivateExample text");
			System.exit(1);
		}
		byte[] plainText = args[0].getBytes("UTF8");
		//
		// get a DES private key
		System.out.println("\nStart generating AES key");
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		Key key = keyGen.generateKey();
		System.out.println("Finish generating AES key");
		//
		// get a DES cipher object and print the provider
		Cipher cipher = Cipher.
		//getInstance("DES/ECB/PKCS5Padding");
		getInstance("AES/ECB/PKCS5Padding");
		System.out.println("\n" + cipher.getProvider().getInfo());
		//
		// encrypt using the key and the plaintext
		System.out.println("\nStart encryption");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(plainText);
		System.out.println("Finish encryption: ");
		byte[] encodedCipher = null;
		System.out.println(new String((encodedCipher  = Base64.encode(cipherText)), "UTF-8"));

		//
		// decrypt the ciphertext using the same key
		System.out.println("\nStart decryption");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] newPlainText = cipher.doFinal(Base64.decode(encodedCipher ));
		System.out.println("Finish decryption: ");

		System.out.println(new String(newPlainText, "UTF8"));
	}
}
