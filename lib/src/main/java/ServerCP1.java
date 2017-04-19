import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;



public class ServerCP1 {
    public static void main(String[] args) throws IOException {
//        ServerSocket serverSocket = new ServerSocket(4321);
//        System.out.println("(... expecting connection ...)");
//        Socket clientSocket = serverSocket.accept();
//        PrintWriter out =
//                new PrintWriter(clientSocket.getOutputStream(), true);
//        BufferedReader in =
//                new BufferedReader(
//                        new InputStreamReader(clientSocket.getInputStream()));







            File file = new File("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/1001831.crt");
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
            fis.read(data);
        System.out.println(new String(data));
//        System.out.println(fis.read(data));
//        fis.read(data);
        fis.close();
        BufferedReader serverCert=new BufferedReader(new FileReader("/Users/zouyun/Desktop/academic-stuff/ProgrammingAssignment2/lib/src/main/java/1001831.crt"));
        //System.out.println(serverCert.read());
        //System.out.println(serverCert.read());

//        clientSocket.close();



    }
}
