package clientSide;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;

public class ClientSocket {
    private String server;
    private int port;
    private Socket socket;
    private InputStream inputStream;
    private OutputStream outputStream;


    public ClientSocket(String server,int port) throws IOException {
        this.port=port;
        this.server=server;
        this.socket= new Socket(this.server,this.port);


        inputStream = socket.getInputStream();
        outputStream = socket.getOutputStream();

    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public OutputStream getOutputStream() {
        return outputStream;
    }

    public void connectToServer(String server, int port) throws IOException {
        this.socket= new Socket(server,port);
        inputStream= socket.getInputStream();
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void sendText(String text) throws IOException {
        DataOutputStream dos = new DataOutputStream(outputStream);
        dos.writeUTF(text);
        dos.flush();
        outputStream.flush();
    }
    public String receiveText() throws IOException {
        DataInputStream dis = new DataInputStream(inputStream);
        String s = dis.readUTF();

        return s;
    }

    public Object receiveObject() throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        Object obj =  ois.readObject();

        return  obj;
    }

    public void sendObject(Serializable object) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(outputStream);
        oos.writeObject(object);
        oos.flush();
        outputStream.flush();
    }

    public void writeKeypair(String file_path, KeyPair keyPair) throws IOException {
        File f = new File(file_path);
        FileOutputStream fos = new FileOutputStream(f);
        ObjectOutputStream obs = new ObjectOutputStream(fos);

        obs.writeObject(keyPair);

    }

    public KeyPair readKeypair(String file_path) throws IOException, ClassNotFoundException {
        File f = new File(file_path);
        FileInputStream fos = new FileInputStream(f);
        ObjectInputStream ios = new ObjectInputStream(fos);

        return (KeyPair)ios.readObject();
    }

    public Object readObject(String file_path) throws IOException, ClassNotFoundException {
        File f = new File(file_path);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException() ;
        }
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(fis);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return ois.readObject();
    }

    public void writeObject(String file_path, Object obj) throws IOException {
        File f = new File(file_path);
        FileOutputStream fos = new FileOutputStream(f);
        ObjectOutputStream obs = new ObjectOutputStream(fos);

        obs.writeObject(obj);
    }


}
