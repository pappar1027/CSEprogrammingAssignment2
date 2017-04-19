import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class ClientCP1 {
    public static void main(String[] args) throws IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        int portNumber = 4321;
        String hostname="localhost";
        Socket clientSocket = new Socket();
        SocketAddress sockaddr = new InetSocketAddress(hostname, portNumber);
        clientSocket.connect(sockaddr, 100);
        System.out.println("connected");
        DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());

        //generate nonce to send
        SecureRandom random = new SecureRandom();
        byte nonce[] = new byte[8];
        random.nextBytes(nonce);
        //send nonce
        dOut.writeInt(nonce.length);
        dOut.write(nonce);

        //receive encrypted nonce
        int EncryptedNonceLength=dIn.readInt();
        byte[] EncryptedNonce = new byte[EncryptedNonceLength];
        dIn.readFully(EncryptedNonce, 0, EncryptedNonce.length);
        System.out.println("encrypted nonce received");

        //ask for cert
        String message="Send your signed certificate";
        byte[] messageBytes = message.getBytes();
        dOut.writeInt(messageBytes.length);
        dOut.write(messageBytes);




//
        //get CA's public key
        InputStream fis = new FileInputStream("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/CA.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
        PublicKey CAkey = CAcert.getPublicKey();


        //// read the cert
        int certLength=dIn.readInt();
        byte[] certdata = new byte[certLength];
        dIn.readFully(certdata, 0, certdata.length);

        InputStream fisServer = new ByteArrayInputStream(certdata);
        CertificateFactory cfServer = CertificateFactory.getInstance("X.509");
        X509Certificate ServerCert =(X509Certificate)cfServer.generateCertificate(fisServer);
        PublicKey ServerPublicKey = ServerCert.getPublicKey();

        //verify Server certicate
        ServerCert.checkValidity();
        ServerCert.verify(CAkey);
        System.out.println("cert verified");

        //verify nonce value
        Cipher decryptcipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptcipher.init(Cipher.DECRYPT_MODE,ServerPublicKey);


        byte[] decryptedNonce=decryptcipher.doFinal(EncryptedNonce);

        //if does not match
        if(!Arrays.equals(nonce,EncryptedNonce)){
            clientSocket.close();
        }






    }
}
