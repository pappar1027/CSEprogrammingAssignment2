import java.io.BufferedInputStream;
import java.io.BufferedReader;
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
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;



public class ClientCP1 {
    public static void main(String[] args) throws IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        int portNumber = 4321;
        String hostname="localhost";
        Socket clientSocket = new Socket();
        SocketAddress sockaddr = new InetSocketAddress(hostname, portNumber);
        clientSocket.connect(sockaddr, 100);
        System.out.println("connected");
        PrintWriter out =
                new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in =
                new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream()));


        String message="Hello from the other side";


//get CA's public key
        InputStream fis = new FileInputStream("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/CA.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
        PublicKey CAkey = CAcert.getPublicKey();

        String serverCertName="/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/1001831.crt";



        //InputStream fisServer = new FileInputStream(serverCertName);
        InputStream fisServer = new BufferedInputStream(clientSocket.getInputStream());//may be problematic
        CertificateFactory cfServer = CertificateFactory.getInstance("X.509");
        X509Certificate ServerCert =(X509Certificate)cfServer.generateCertificate(fisServer);
        PublicKey ServerPublicKey = ServerCert.getPublicKey();
        //verify Server certicate
        ServerCert.checkValidity();
        ServerCert.verify(CAkey);

    }
}
