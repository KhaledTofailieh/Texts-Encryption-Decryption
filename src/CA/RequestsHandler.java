package CA;

import Protocol.Request;
import Protocol.Response;
import serverSide.ServerSocket;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

public class RequestsHandler extends Thread{

    private InputStream inputStream;
    private OutputStream outputStream;
    private ServerSocket serverSocket;
    private HashMap giftCertifications;
    private KeyPair serverKey;
    private Socket socket;
    private String CAName;

    RequestsHandler(Socket socket, KeyPair serverKey, HashMap giftCertifications,String CAName) throws IOException {
        this.socket = socket;
        this.serverKey=serverKey;
        this.giftCertifications= giftCertifications;
        this.CAName = CAName;
    }
    public void run() {
        try {
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();
            this.serverSocket = new ServerSocket(inputStream,outputStream);

            while (socket.isBound() && !socket.isClosed()){
                Request req = (Request)this.serverSocket.receiveObject();
                this.do_action(req);
            }

        }catch (IOException | ClassNotFoundException | IllegalBlockSizeException | NoSuchPaddingException
                | BadPaddingException | NoSuchAlgorithmException | InvalidKeyException ignored){
            ignored.printStackTrace();
        }finally {
            try {
                if (socket != null)
                    socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    void  do_action(Request req) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Response res;
        switch(req.getHeader().getMethod()){
            case get:{
             Getter getter = new Getter(req,this.serverKey,this.giftCertifications,this.CAName);
             res =getter.getResponse();
                break;

            } default:{
            res = new Response();
            res.getHeader().setStatus(400);
            res.getBody().put("msg","Not Defined Operator");

            }
        }
       this.serverSocket.sendObject(res);
    }

}
