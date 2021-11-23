package serverSide;

import java.io.*;

public class ServerSocket {
    private InputStream inputStream;
    private OutputStream outputStream;

    public ServerSocket(InputStream inputStream, OutputStream outputStream){
        this.inputStream=inputStream;
        this.outputStream = outputStream;
    }

    public void sendObject(Serializable obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(outputStream);
        oos.writeObject(obj);
        oos.flush();
        outputStream.flush();

    }
    public Object receiveObject() throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        Object obj =  ois.readObject();

        return  obj;
    }
    String receiveText() throws IOException {
        DataInputStream dis = new DataInputStream(inputStream);
        return dis.readUTF();
    }
    public void sendText(String text){
        try {
            DataOutputStream dos = new DataOutputStream(outputStream);
            dos.writeUTF(text);

            dos.flush();
            outputStream.flush();

        } catch (IOException  e) {
            e.printStackTrace();
        }
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
}
