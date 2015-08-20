package crypto.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SymmetricEncryption {
	private static String provider = "BC";
	//private static String provider = "SunJCE";
	private String algorithm;
	private String mode;
	private Cipher cipher;

	/**
	 * Creates a new instance of SymmetricEncryption, but allows the user to manually set the algorithm and mode
	 * @author Rafael Will M. de Araujo
	 * @param algorithm Algorithm to be used
	 * @param mode Block cipher mode of operation (CBC is highly recommended)
	 */
	public SymmetricEncryption(String algorithm, String mode){
		try{
			this.algorithm = algorithm;
			this.mode = mode;
			this.cipher = Cipher.getInstance(this.algorithm + "/" + this.mode + "/PKCS5Padding", provider);
		} catch(Exception e){
			e.printStackTrace();
		}
	}
	
	/**
	 * Creates a new instance of SymmetricEncryption
	 * @author Rafael Will M. de Araujo
	 * @param securityType Type of security to be used, according to SecurityType class (WEAK or STRONG).
	 */
	public SymmetricEncryption(int securityType){
		try{
			if (securityType == SecurityType.WEAK){
				this.algorithm = "DESede";
				this.mode = "CBC";
			} else{ // STRONG
				this.algorithm = "AES";
				this.mode = "CBC";
			}
			this.cipher = Cipher.getInstance(this.algorithm + "/" + this.mode + "/PKCS5Padding", provider);
		} catch(NoSuchPaddingException e)
		{
			System.out.println("Error: incorrect padding.");
			e.printStackTrace();
		} catch(NoSuchAlgorithmException e)
		{
			System.out.println("Error: AES algorithm not found.");
			e.printStackTrace();
		} catch(NoSuchProviderException e){
			System.out.println("Error: provider \"" + this.provider + "\" may be not installed.");
			e.printStackTrace();
		} catch(Exception e){
			e.printStackTrace();
		}
	}
	
	/**
	 * Encrypts a byte array
	 * @author Rafael Will M. de Araujo
	 * @param plainInformation The plain information to be encrypted
	 * @param secretKey The secret key to encrypt the information
	 * @param IV The Initialization Vector for CBC mode
	 * @return The encrypted information
	 */
	public byte[] encrypt(byte[] plainInformation, byte[] secretKey, byte[] IV){
		try{
			SecretKeySpec key = new SecretKeySpec(secretKey, this.algorithm);
			this.cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
			return this.cipher.doFinal(plainInformation);
		} catch(Exception e){
			e.printStackTrace();
			return new byte[]{};
		}
	}
	
	/**
	 * Encrypts a byte array
	 * @author Rafael Will M. de Araujo
	 * @param plainInformation The plain information to be encrypted
	 * @param secretKey The secret key to encrypt the information
	 * @return The encrypted information
	 */
	public byte[] encrypt(byte[] plainInformation, byte[] secretKey){
		try{
			SecretKeySpec key = new SecretKeySpec(secretKey, this.algorithm);
			this.cipher.init(Cipher.ENCRYPT_MODE, key);
			return this.cipher.doFinal(plainInformation);
		} catch(Exception e){
			e.printStackTrace();
			return new byte[]{};
		}
	}

	/**
	 * Decrypts a byte array
	 * @author Rafael Will M. de Araujo
	 * @param encryptedInformation The encrypted information to be decrypted
	 * @param secretKey The secret key to decrypt the information
	 * @param IV The Initialization Vector for CBC mode
	 * @return The decrypted information
	 */
	public byte[] decrypt(byte[] encryptedInformation, byte[] secretKey, byte[] IV){
		try{
			SecretKeySpec key = new SecretKeySpec(secretKey, this.algorithm);
			this.cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
			return this.cipher.doFinal(encryptedInformation);
		} catch(Exception e){
			e.printStackTrace();
			return new byte[]{};
		}
	}
	
	/**
	 * Decrypts a byte array
	 * @author Rafael Will M. de Araujo
	 * @param encryptedInformation The encrypted information to be decrypted
	 * @param secretKey The secret key to decrypt the information
	 * @return The decrypted information
	 */
	public byte[] decrypt(byte[] encryptedInformation, byte[] secretKey){
		try{
			SecretKeySpec key = new SecretKeySpec(secretKey, this.algorithm);
			this.cipher.init(Cipher.DECRYPT_MODE, key);
			return this.cipher.doFinal(encryptedInformation);
		} catch(Exception e){
			e.printStackTrace();
			return new byte[]{};
		}
	}
	
	/**
	 * Use this method to print a byte array
	 * @author Rafael Will M. de Araujo
	 * @param s The array description
	 * @param arr The array to be printed
	 */
	public static void printByteArray(String s, byte[] arr){
		int i;
		System.out.print(s + ": [");
		for(i=0;i<arr.length-1;++i){
			System.out.print(arr[i] + ", ");
		}
		System.out.print(arr[arr.length-1]);
		System.out.print("]  length: (" + arr.length + ")\n");
	}
	
	/**
	 * This method should be used for tests only.
	 * @author Rafael Will M. de Araujo
	 * @param args
	 */
	public static void main(String [] args) {
		Security.addProvider(new BouncyCastleProvider());
		try {
	    	// http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html
			//http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#AppC
	    	//byte[] key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31}; // 256 bits key
			//byte[] key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23}; // 192 bits key
			byte[] key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; // 128 bits key
			
			byte[] plain = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
	    	byte[] iv = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; // IV has 128 bits (block size for AES is 128 bits)
	    	printByteArray("Key", key);
	    	printByteArray("IV", iv);
	    	printByteArray("Plain", plain);
	    	System.out.println("- - - - - - - - - - -");
	    	SymmetricEncryption se = new SymmetricEncryption(SecurityType.STRONG);
	    	byte[] enc = se.encrypt(plain, key, iv);
	    	printByteArray("Encrypted", enc);
	    	byte[] dec = se.decrypt(enc, key, iv);
	    	printByteArray("Decrypted", dec);
	    } catch(Exception e){
	    	e.printStackTrace();
	    	System.out.println(e.getMessage());
	    }
	 
	}
	
	
	/**
	 * This method should be used for tests only.
	 * @author Rafael Will M. de Araujo
	 * @param args
	 */
	public static void main2(String [] args) {
		Security.addProvider(new BouncyCastleProvider());
	    try {
	    	// http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html
	    	byte[] plain = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
	    	
	    	/* key should be 16 bytes (only allowed in Bouncy Castle) or 24 bytes for 3DES (allowed in both Bouncy Castle or Sun default provider)
	    	16 bytes = 112 bits key (double DES) => 16 bits for parity
	    	24 bytes = 168 bits key (triple DES) => 24 bits for parity
	    	*/
	    	//byte[] key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23}; // 168 bits key
	    	byte[] key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; // 112 bits key
	    	
	    	byte[] iv = {0,1,2,3,4,5,6,7}; // IV has 64 bits (block size for 3DES is 64 bits)
	    	printByteArray("Key", key);
	    	printByteArray("IV", iv);
	    	printByteArray("Plain", plain);
	    	System.out.println("- - - - - - - - - - -");
	    	SymmetricEncryption se = new SymmetricEncryption(SecurityType.WEAK);
	    	byte[] enc = se.encrypt(plain, key, iv);
	    	printByteArray("Encrypted", enc);
	    	byte[] dec = se.decrypt(enc, key, iv);
	    	printByteArray("Decrypted", dec);
	    } catch(Exception e){
	    	e.printStackTrace();
	    	System.out.println(e.getMessage());
	    }
	 
	}
}
