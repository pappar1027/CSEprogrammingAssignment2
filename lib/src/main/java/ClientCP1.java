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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;

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
        System.out.println("cert verified by CA key");

        //verify nonce value
        Cipher decryptcipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptcipher.init(Cipher.DECRYPT_MODE,ServerPublicKey);


        byte[] decryptedNonce=decryptcipher.doFinal(EncryptedNonce);

        //if does not match
        if(!Arrays.equals(nonce,decryptedNonce)){
            clientSocket.close();
            return;
        }
        System.out.println("server verified");


        //parse file to byte array
        File fileToSend=new File("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/largeFile.txt");
        InputStream filetoSendis=new FileInputStream(fileToSend);

        byte[] fileToSendBytes=new byte[(int)fileToSend.length()];
        filetoSendis.read(fileToSendBytes);

        //the length of byte array of the file
        System.out.println(fileToSendBytes.length);

        //encrypt by blocks of 117
        int numOfBlocks= (int)Math.ceil(fileToSendBytes.length/117);// next largest int
        ArrayList<byte[]> byteBlocks=new ArrayList<>();

        int bytelen=0;
        for(int i=0;i<numOfBlocks+1;i++){
            if(i<numOfBlocks){

                byte[] segment=Arrays.copyOfRange(fileToSendBytes,i*117,(i+1)*117);
                Cipher Filecipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
                Filecipher.init(Cipher.ENCRYPT_MODE,ServerPublicKey);
                byte[] EncryptedFileToSend=Filecipher.doFinal(segment);
                byteBlocks.add(EncryptedFileToSend);
                bytelen+=EncryptedFileToSend.length;}
            else{
                byte[] segment=Arrays.copyOfRange(fileToSendBytes,i*117,fileToSendBytes.length);
                Cipher Filecipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
                Filecipher.init(Cipher.ENCRYPT_MODE,ServerPublicKey);
                byte[] EncryptedFileToSend=Filecipher.doFinal(segment);
                byteBlocks.add(EncryptedFileToSend);
                bytelen+=EncryptedFileToSend.length;

            }

        }
        int arrayposition=0;
        byte[] CompletelyEncryptedFile=new byte[bytelen];
        for(int i=0;i<byteBlocks.size();i++){
            System.arraycopy(byteBlocks.get(i),0,CompletelyEncryptedFile,arrayposition,byteBlocks.get(i).length);
            arrayposition+=byteBlocks.get(i).length;
        }


        //upload the encrypted file
        dOut.writeInt(CompletelyEncryptedFile.length);
        dOut.write(CompletelyEncryptedFile);


    }
}
