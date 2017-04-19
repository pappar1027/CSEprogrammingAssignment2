

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class CP2Client {
	
	private static Socket clientSocket = new Socket();
	private static SocketAddress addr;
	private static SecureRandom secure = new SecureRandom();
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		addr = new InetSocketAddress("localhost",4321);
		
		//Client the socket to the address
		try {
			clientSocket.connect(addr, 100);
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		//Let's define our output stream
		PrintWriter out = null;
		try {
			out = new PrintWriter(clientSocket.getOutputStream(),true);
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		//Let's define our input stream
		DataInputStream in = null;
		try {
			in = new DataInputStream(clientSocket.getInputStream());
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		//Create a client identity in terms of a random string of length
		String identity = new BigInteger(130,secure).toString(32);
		System.out.println("Client Identity: "+ identity);
		
		//Send the client identity to the server
		out.println(identity);
		
		//Wait for reply back from server
		byte[] encryptedReply = new byte[in.readInt()];
		in.readFully(encryptedReply, 0, encryptedReply.length);
		
		//Request certificate from server
		out.println("Request Cert");

		//get CA's key
		InputStream fis = new FileInputStream("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/CA.crt");
		CertificateFactory cf = null;
		PublicKey CAkey=null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
			CAkey = CAcert.getPublicKey();
		} catch (CertificateException e) {
			e.printStackTrace();
		}


		
		//Send in the size of the cert to the client
		byte[] cert = new byte[in.readInt()];
		
		if (cert.length > 0) {
			
			in.readFully(cert,0,cert.length);
			InputStream fisServer = new ByteArrayInputStream(cert);
			
			//Generate server instance
			CertificateFactory cfServer;
			PublicKey ServerPublicKey = null;
			
			try {
				
				cfServer = CertificateFactory.getInstance("X.509");
				X509Certificate ServerCert =(X509Certificate)cfServer.generateCertificate(fisServer);
		        ServerPublicKey = ServerCert.getPublicKey();
				//verify Server certicate
				ServerCert.checkValidity();
				ServerCert.verify(CAkey);
				System.out.println("cert verified by CA key");
		         
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}


			
			byte[] outputMessage = null;
		    try {
				Cipher rsaCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, ServerPublicKey);
				outputMessage = rsaCipherDecrypt.doFinal(encryptedReply);
				
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
		    String verification = new String(outputMessage);
		    
		    if (verification.equals(identity)) {
		    	
		    	System.out.println("Server is verified, start sending data");
		    	
		    	//Data, read from a file
		    	String FileName = "/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/smallFile.txt";
		    	FileReader fr = new FileReader(FileName);
		    	BufferedReader br = new BufferedReader(fr);
		    	String data = "";
		    	String eachLine = null;
		    	
		    	while((eachLine = br.readLine()) != null) {
		    		data+=eachLine;
		    	}
		    	
		    	//Generate the random AES key
		    	SecureRandom secure = new SecureRandom();
		    	byte[] aesRandomKey = new byte[16];
		    	secure.nextBytes(aesRandomKey);
		    	SecretKey secret = new SecretKeySpec(aesRandomKey,"AES");
		    	
		    	byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			    IvParameterSpec ivspec = new IvParameterSpec(iv);
			    
		    	//Use the AES key to encrypt some data
		    	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		    	try {
					cipher.init(Cipher.ENCRYPT_MODE, secret,ivspec);
				} catch (InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		    	byte[] encryptedData = cipher.doFinal(data.getBytes());
		    	
		    	//Encrypt the key itself, and then send it across
		    	Cipher rsaPublicKeyEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		    	rsaPublicKeyEncrypt.init(Cipher.ENCRYPT_MODE, ServerPublicKey);
		    	byte[] encryptedAESKey = rsaPublicKeyEncrypt.doFinal(aesRandomKey);
		    	
		    	out = null;
		    	DataOutputStream dostream = new DataOutputStream(clientSocket.getOutputStream());
		    	dostream.writeInt(encryptedAESKey.length);
		    	dostream.write(encryptedAESKey);
		    	dostream.writeInt(encryptedData.length);
		    	dostream.write(encryptedData);
		    	System.out.println("All data sent");
		    }

		}
		
		
		
	}

}
