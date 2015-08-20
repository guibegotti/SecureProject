package crypto.symmetric.bench;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import crypto.symmetric.SecurityType;
import crypto.symmetric.SymmetricEncryption;

public class Benchmark {
	
	private static Scanner scanner = new Scanner(System.in);

	/**
	 * Reads an input from keyboard.
	 * @author Rafael Will M. de Araujo
	 * @param msg Message to be displayed.
	 * @return An user inputed text.
	 */
	private static String readStringInput(String msg){
		System.out.print(msg);
		return scanner.nextLine();
	}
	
	private static void printByteArray(String s, byte[] arr){
		int i;
		System.out.print(s + ": [");
		for(i=0;i<arr.length-1;++i){
			System.out.print(arr[i] + ", ");
		}
		System.out.print(arr[arr.length-1]);
		System.out.print("] (length: (" + arr.length + ")\n");
	}
	
	private static void printLongArrayAsRArray(String variableName, long[] arr){
		int i;
		System.out.print(variableName + " <- c(");
		for(i=0; i<arr.length-1;++i)
			System.out.print(arr[i] + ",");
		System.out.print(arr[arr.length-1]);
		System.out.print(")\n");
	}
	
	/**
	 * Generates a secure random array.
	 * @author Rafael Will M. de Araujo
	 * @param size Size of the output array.
	 * @return A secure random array of bytes of fixed size.
	 */
	private static byte[] generateRandomByteArray(int size){
		/*
		 * Based on: http://developer.android.com/reference/java/security/SecureRandom.html
		 * According to the source above, seeding SecureRandom class is INSECURE.
		 */
		SecureRandom sr = new SecureRandom();
		byte[] output = new byte[size];
		sr.nextBytes(output);
		return output;
	}
	
	/**
	 * Generates a set of random arrays (based on SecureRandom class)
	 * @author Rafael Will M. de Araujo
	 * @param numberOfArrays Number of arrays to be generated.
	 * @param arraySize The size of each array to be generated.
	 * @return A matrix of secure random arrays.
	 */
	private static byte[][] generateRandomByteArrays(int numberOfArrays, int arraySize){
		byte[][] keys = new byte[numberOfArrays][arraySize];
		int i;
		for(i=0; i<numberOfArrays; ++i)
			keys[i] = generateRandomByteArray(arraySize);
		return keys;
	}
	
	private static void benchAES(int qtdOfTests, int[] keySizes, int[] dataSizes){
		int test, benchRun;
		SymmetricEncryption se = new SymmetricEncryption(SecurityType.STRONG);
		byte[][] IVs = generateRandomByteArrays(qtdOfTests, 16);
		
		for(int dataSize : dataSizes){
			byte[][] data = generateRandomByteArrays(qtdOfTests, dataSize*1024);
			benchRun = 0;
			
			for(int keySize : keySizes){
				byte[][] keys = generateRandomByteArrays(qtdOfTests, keySize/8);
				long[] encryptTimes = new long[qtdOfTests];
				long[] decryptTimes = new long[qtdOfTests];
				
				for(test=0; test<qtdOfTests; ++test){
					long startTime, estimatedTime;
					byte[] info;
					//printByteArray("org", data[test]);
					startTime = System.nanoTime();
					info = se.encrypt(data[test], keys[test], IVs[test]);
					estimatedTime = System.nanoTime() - startTime;
					encryptTimes[test] = estimatedTime;
					//printByteArray("enc", info);
					
					startTime = System.nanoTime();
					info = se.decrypt(info, keys[test], IVs[test]);
					estimatedTime = System.nanoTime() - startTime;
					decryptTimes[test] = estimatedTime;
					//printByteArray("dec", info);
					
					/*
					if (!info.equals(data[test])){
						throw new Exception("Wrong decryption: Test(" + test + "), KeySize(" + keySize + "), DataSize(" + dataSize + ").");
					}*/
					
				}
				if (benchRun > 0){
					printLongArrayAsRArray("AES_Ek"+keySize+"d"+dataSize, encryptTimes);
					printLongArrayAsRArray("AES_Dk"+keySize+"d"+dataSize, decryptTimes);
				}
				benchRun++;
			}
			System.out.print("\n");
		}
	}
	
	private static void bench3DES(int qtdOfTests, int[] keySizes, int[] dataSizes){
		int test, benchRun;
		SymmetricEncryption se = new SymmetricEncryption(SecurityType.WEAK);
		byte[][] IVs = generateRandomByteArrays(qtdOfTests, 8);
		
		for(int dataSize : dataSizes){
			byte[][] data = generateRandomByteArrays(qtdOfTests, dataSize*1024);
			benchRun = 0;
			
			for(int keySize : keySizes){
				int trueKeySize = 24; // 168 bits (because 24 bits are used for parity)
				if (keySize == 112)
					trueKeySize = 16; // 112 bits (because 16 bits are used for parity)
				byte[][] keys = generateRandomByteArrays(qtdOfTests, trueKeySize);
				long[] encryptTimes = new long[qtdOfTests];
				long[] decryptTimes = new long[qtdOfTests];
				
				for(test=0; test<qtdOfTests; ++test){
					long startTime, estimatedTime;
					byte[] info;
					//printByteArray("org", data[test]);
					startTime = System.nanoTime();
					info = se.encrypt(data[test], keys[test], IVs[test]);
					estimatedTime = System.nanoTime() - startTime;
					encryptTimes[test] = estimatedTime;
					//printByteArray("enc", info);
					
					startTime = System.nanoTime();
					info = se.decrypt(info, keys[test], IVs[test]);
					estimatedTime = System.nanoTime() - startTime;
					decryptTimes[test] = estimatedTime;
					//printByteArray("dec", info);
					
				}
				if (benchRun > 0){
					printLongArrayAsRArray("DESede_Ek"+keySize+"d"+dataSize, encryptTimes);
					printLongArrayAsRArray("DESede_Dk"+keySize+"d"+dataSize, decryptTimes);
				}
				benchRun++;
			}
			System.out.print("\n");
		}
	}

	private static void benchGeneric(int qtdOfTests, int[] keySizes, int[] dataSizes, String algorithm){
		int test, benchRun;
		SymmetricEncryption se = new SymmetricEncryption(algorithm, "CBC");
		byte[][] IVs = generateRandomByteArrays(qtdOfTests, 16);
		
		for(int dataSize : dataSizes){
			byte[][] data = generateRandomByteArrays(qtdOfTests, dataSize*1024);
			benchRun = 0;
			
			for(int keySize : keySizes){
				byte[][] keys = generateRandomByteArrays(qtdOfTests, keySize/8);
				long[] encryptTimes = new long[qtdOfTests];
				long[] decryptTimes = new long[qtdOfTests];
				
				for(test=0; test<qtdOfTests; ++test){
					long startTime, estimatedTime;
					byte[] info;
					//printByteArray("org", data[test]);
					startTime = System.nanoTime();
					info = se.encrypt(data[test], keys[test],IVs[test]);
					estimatedTime = System.nanoTime() - startTime;
					encryptTimes[test] = estimatedTime;
					//printByteArray("enc", info);
					
					startTime = System.nanoTime();
					info = se.decrypt(info, keys[test], IVs[test]);
					estimatedTime = System.nanoTime() - startTime;
					decryptTimes[test] = estimatedTime;
					//printByteArray("dec", info);
					
					/*
					if (!info.equals(data[test])){
						throw new Exception("Wrong decryption: Test(" + test + "), KeySize(" + keySize + "), DataSize(" + dataSize + ").");
					}*/
					
				}
				if (benchRun > 0){
					printLongArrayAsRArray("_Ek"+keySize+"d"+dataSize, encryptTimes);
					printLongArrayAsRArray("_Dk"+keySize+"d"+dataSize, decryptTimes);
				}
				benchRun++;
			}
			System.out.print("\n");
		}
	}

	
	/**
	 * Runs a benchmark according to the specified cryptographic algorithm. Prints arrays in R language format for statistical analysis (more info at: http://www.r-project.org)
	 * @author Rafael Will M. de Araujo
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		int qtdOfTests = 100; // quantity of tests for each key size, for each data size (total of tests: dataSizes * keySizes)
		int[] dataSizes = {1,4,16,64,256,1024,2048}; // size of data to encrypted (in KB)
		try{
			String strAlgorithm = readStringInput("Enter the algorithm (AES/3DES): ").toUpperCase().trim();
			if (strAlgorithm.equals("AES")){
				int[] keySizes = {128,128, 192, 256}; // key sizes in bits
				benchAES(qtdOfTests, keySizes, dataSizes);
			}
			else
				if (strAlgorithm.equals("3DES")){
					int[] keySizes = {168, 168};//112,112, 168}; // key sizes in bits
					bench3DES(qtdOfTests, keySizes, dataSizes);
				}
				else{
					int [] keySizes = {128, 128};
					// http://www.bouncycastle.org/specifications.html
					benchGeneric(qtdOfTests, keySizes, dataSizes, "Serpent");
				}
			System.out.println("\nFinished.");
		} catch(Exception e){
			e.printStackTrace();
		}
	}

}
