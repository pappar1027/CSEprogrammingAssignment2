import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class CP2Server {
	
	private static ServerSocket serverSocket;
	private static Socket clientSocket;
	
	public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		//Declare new socket and get ready to act as server
		try {
			serverSocket = new ServerSocket(4321);
			System.out.println("expecting connection");
			clientSocket = serverSocket.accept();
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		//Get data stream of the client socket
		DataOutputStream out = null;
		try {
			out = new DataOutputStream(clientSocket.getOutputStream());
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		//Create an input stream for the client socket
		BufferedReader in = null;
		try {
			in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//Read in the identity of the client
		String inputMessage = null;
		try {
			inputMessage = in.readLine();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//Generate private key from file here:
		String privateKeyFileName = "/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/privateServer.der";
		Path path = Paths.get(privateKeyFileName);
		byte[] privKeyByteArray = Files.readAllBytes(path);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
		KeyFactory keyFactory = null;
		
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		
		RSAPrivateKey  privateKey = null;
		try {
			 privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
			ex.printStackTrace();
		}
				
		//Use this new found knowledge to send to the client
		Cipher rsaCipher;
		try {
			rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			
			byte[] encryptedMessage = rsaCipher.doFinal(inputMessage.getBytes());
			out.writeInt(encryptedMessage.length);
			out.write(encryptedMessage);
		
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
			ex.printStackTrace();
		}
		
		//Send the cert if the client requests for cert
		try {
			if (in.readLine().equals("Request Cert")) {
				File file = new File("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/1001827.crt");
		        FileInputStream fis = new FileInputStream(file);
		        byte[] certdata = new byte[(int) file.length()];
		        fis.read(certdata);
		        out.writeInt(certdata.length);
		        out.write(certdata);
			}
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		in = null;
		
		DataInputStream instream = new DataInputStream(clientSocket.getInputStream());
		
		//Receive key
		byte[] encryptedKey = null;
		byte[] encryptedData = null;
		try {
			encryptedKey = new byte[instream.readInt()];
			instream.readFully(encryptedKey, 0, encryptedKey.length);
			encryptedData = new byte[instream.readInt()];
			instream.readFully(encryptedData, 0, encryptedData.length);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
		//Decrypt the key
		Cipher rsaPrivateKeyDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaPrivateKeyDecrypt.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] aesKey = rsaPrivateKeyDecrypt.doFinal(encryptedKey);
		
		SecretKey secret = new SecretKeySpec(aesKey,"AES");
		
		//Decrypt the message itself
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	    IvParameterSpec ivspec = new IvParameterSpec(iv);
	    
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	try {
			cipher.init(Cipher.DECRYPT_MODE, secret,ivspec);
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	byte[] decryptedData = cipher.doFinal(encryptedData);
//		System.out.println(new String(decryptedData));
		
	}
}
