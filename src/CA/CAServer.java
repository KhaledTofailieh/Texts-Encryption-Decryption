package CA;
import crypto.KeysGenerator;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.HashMap;

public class CAServer extends Thread {
    int port;
    private String name;
    private ServerSocket serverSocket;
    private KeyPair keyPair;
    private HashMap giftCertificates;


    public CAServer(String ca_name,int port) throws Exception {
        this.port = port;
        this.name = ca_name;
        this.serverSocket = new ServerSocket(port);
        try {
            this.giftCertificates= (HashMap) readObject("gift_certificates");
        }catch (Exception e){
            this.giftCertificates= new HashMap();
        }
        try {
            this.keyPair= (KeyPair) this.readObject("ca_keys");
            System.out.println("load CA keys>>");
        } catch (Exception e) {

            this.keyPair= KeysGenerator.generateKeyPair(2048);
            this.writeObject("ca_keys",this.keyPair);
            System.out.println("generate CA keys>>");
        }

        System.out.println("CA Server Run On: "+port);
    }

    public void writeObject(String file_path, Object obj) throws IOException {
        File f = new File(file_path);
        FileOutputStream fos = new FileOutputStream(f);
        ObjectOutputStream obs = new ObjectOutputStream(fos);

        obs.writeObject(obj);
    }

    public Object readObject(String file_path) throws IOException, ClassNotFoundException {
        File f = new File(file_path);
        FileInputStream fos = new FileInputStream(f);
        ObjectInputStream ios = new ObjectInputStream(fos);

        return ios.readObject();
    }
    @Override
    public void run() {

        while(serverSocket.isBound() && !serverSocket.isClosed()){
            Socket socket;
            try {
                socket = serverSocket.accept();
                RequestsHandler requestsHandler = new RequestsHandler(socket,this.keyPair,this.giftCertificates,this.name);
                requestsHandler.start();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}

