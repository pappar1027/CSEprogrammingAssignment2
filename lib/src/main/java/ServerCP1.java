import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class ServerCP1 {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, SignatureException, BadPaddingException, IllegalBlockSizeException {
        ServerSocket serverSocket = new ServerSocket(4321);
        System.out.println("(... expecting connection ...)");
        Socket clientSocket = serverSocket.accept();
        DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
        //read cert
        File certfile = new File("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/1001827.crt");
        FileInputStream fis = new FileInputStream(certfile);
        byte[] certdata = new byte[(int) certfile.length()];
        fis.read(certdata);

        File pubKeyFile =new File("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/publicServer.der");
        File privKeyFile =new File("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/privateServer.der");


        // read public key DER file
        DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
        byte[] pubKeyBytes = new byte[(int)pubKeyFile.length()];
        dis.readFully(pubKeyBytes);

        dis.close();

        // read private key DER file
        dis = new DataInputStream(new FileInputStream(privKeyFile));
        byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
        dis.read(privKeyBytes);

        dis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");;
//
//
//        // decode public key
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        RSAPublicKey pubKey=(RSAPublicKey) keyFactory.generatePublic(pubSpec);
//

//        // decode private key
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey= (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
//
////
////        //receive nonce
        int nonceLength=dIn.readInt();
        byte[] nonce = new byte[nonceLength];
        dIn.readFully(nonce, 0, nonce.length);
//
//        //encrypt nonce with privateKey
        Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,privKey);
        byte[] encryptedNonce=cipher.doFinal(nonce);

        //send encrypted nonce
        dOut.writeInt(encryptedNonce.length);
        dOut.write(encryptedNonce);
        System.out.println("encrypted nonce sent");

        //if ask for cert:
        int MessageLength=dIn.readInt();
        byte[] messageBytes = new byte[MessageLength];
        dIn.readFully(messageBytes, 0, messageBytes.length);
        String message=new String(messageBytes);
        System.out.println(message);
        if(message.equals("Send your signed certificate")){
            //        //send cert over in bytes
            dOut.writeInt(certdata.length);
            dOut.write(certdata);
            fis.close();
            System.out.println("cert sent");

        }








//        Signature signer = Signature.getInstance("SHA1withRSA");
//        signer.initSign(privKey); // PKCS#8 is preferred
//        signer.update(nonce);
//        byte[] signature = signer.sign();

//        byte[] encryptedNonce=cipher.doFinal(nonce);




//
////        clientSocket.close();



    }
}
