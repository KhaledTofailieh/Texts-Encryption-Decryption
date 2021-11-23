package serverSide;

import CA.CA;
import CA.Certificate;
import Protocol.*;
import clientSide.ClientSocket;
import crypto.KeysGenerator;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.HashMap;

public class Server extends Thread {
    int port;

    private ServerSocket serverSocket;
    private KeyPair keyPair;
    private HashMap loginClients;
    private  HashMap editPermission;
    private Certificate certificate;
    private CA CA;
    private String serverName;
    public int getPort() {
        return port;
    }

    public Server(int port,String serverName) throws Exception {
        this.port = port;
        this.serverName= serverName;
        this.serverSocket = new ServerSocket(port);
        this.loginClients = new HashMap();
        try {
            this.editPermission = (HashMap) readObject("editPermission");
        }catch (Exception e){
            this.editPermission= new HashMap();
        }

        try {
            this.keyPair= (KeyPair) this.readObject("server_keys");
            System.out.println("load server keys>>");
        } catch (Exception e) {

            this.keyPair= KeysGenerator.generateKeyPair(2048);
            this.writeObject("server_keys",this.keyPair);
            System.out.println("generate server keys>>");
        }
        try {
           this.certificate = (Certificate) this.readObject("server_certificate");
           System.out.println("Load Server Certificate>>");
        }catch (FileNotFoundException e){
            System.out.println("Request Server Certificate>>");
            this.certificate = this.requestCertificate("127.0.0.1",9999);
            if(this.certificate!= null){
                this.writeObject("server_certificate",this.certificate);
            }

        }

        this.CA =this.requestCAKey("127.0.0.1",9999);
        System.out.println("Server Run On: "+port);
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

    Certificate requestCertificate(String CAUrl ,int port) {
        try {
            ClientSocket clientSocket = new ClientSocket(CAUrl,port);

            Request request = new Request(Methods.get, Query.Certificate);
            request.getBody().put("public",this.keyPair.getPublic());
            request.getBody().put("serverName",this.serverName);

            clientSocket.sendObject(request);
            Response response = (Response) clientSocket.receiveObject();
            if(!BadStatus.inBads(response.getHeader().getStatus())){
                return  (Certificate) response.getBody().get("certificate");
            }
            return null;
        }catch (IOException | ClassNotFoundException e){
            System.out.println("null value");
           return null;
        }

    }
    CA requestCAKey(String CAUrl ,int port) throws IOException, ClassNotFoundException {
        ClientSocket clientSocket = new ClientSocket(CAUrl,port);

        Request request = new Request(Methods.get, Query.public_key);
        clientSocket.sendObject(request);

        Response response = (Response) clientSocket.receiveObject();
        if(!BadStatus.inBads(response.getHeader().getStatus())){
            return  (CA) response.getBody().get("ca");
        }
        return null;
    }

    @Override
    public void run() {

        while(serverSocket.isBound() && !serverSocket.isClosed()){
            Socket socket;
            try {
                socket = serverSocket.accept();
                RequestWorker requestWorker = new RequestWorker(socket, keyPair, loginClients, editPermission,
                        this.certificate, this.CA.getPublicKey());
                requestWorker.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

}
