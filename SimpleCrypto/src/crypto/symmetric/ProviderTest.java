package crypto.symmetric;

import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProviderTest {
	/**
	 * Checks the default provider being used, and checks if Bouncy Castle provider is installed
	 * @author Rafael Will M. de Araujo
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		// TODO Auto-generated method stub
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			System.out.println("The default provider is: \""
					+ cipher.getProvider() + "\"");
			if (Security.getProvider("BC") == null) {
				System.out.println("\"Bouncy Castle\" provider NOT installed.");
			} else {
				System.out.println("Bouncy Castle is installed.");
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
}
