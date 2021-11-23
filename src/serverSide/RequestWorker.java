package serverSide;

import CA.Certificate;
import Protocol.EncryptionWay;
import Protocol.Query;
import Protocol.Request;
import Protocol.Response;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;

public class RequestWorker extends Thread{
    private InputStream inputStream;
    private OutputStream outputStream;
    private HashMap<String, String> loginClients;
    private HashMap editPermission;
    private Socket socket;
    private ServerSocket serverSocket;
    private KeyPair serverKey;
    private String sessionKey;
    private PublicKey clientKey;
    private Certificate certificate;
    private PublicKey CAKey;

    RequestWorker(Socket socket, KeyPair serverKey, HashMap loginClients, HashMap editPermission, Certificate certificate,PublicKey CAKey) throws IOException {
        this.socket = socket;
        this.serverKey=serverKey;
        this.loginClients= loginClients;
        this.editPermission= editPermission;
        this.certificate = certificate;
        this.CAKey =CAKey;
    }

    private void do_action(Request req){
        Response res = null;
        try{
            switch (req.getHeader().getMethod()){
                case get:{
                    Getter getter  = new Getter(this.serverKey,this.sessionKey,this.certificate);
                    res = getter.getResponse(req);
                    this.serverSocket.sendObject(res);
                    break;
                    }
                case edit:{
                 break;
                }

                case add:{
                Decoder decoder = new Decoder(req,this.serverKey);
                Adder adder;
                res = new Response();

                switch ((Query)req.getParams().get("query")){
                    case session_key:{
                        this.sessionKey = decoder.decodeSessionKey(this.serverKey.getPrivate());
                        System.out.println("session: "+this.sessionKey);
                        break;
                    }
                    case public_key:{
                        clientKey = decoder.decodePublicKey();
                        this.loginClients.putIfAbsent(Base64.getEncoder().encodeToString(clientKey.getEncoded()), "ok");
//                        this.editPermission.putIfAbsent(clientKey,"ok");
//                        this.serverSocket.writeObject("editPermission",editPermission);
                        break;
                    }
                    case file:{
                        String text;
                        String file_path = (String) req.getParams().get("file_path");

                        switch ((EncryptionWay) req.getParams().get("enc_way")){
                            case Symmetric:{
                                String ck = (String) req.getParams().get("pk");
                                if(editPermission.get(ck).equals("ok")){

                                    text=  decoder.decodeTextSymmetric();
                                    adder = new Adder(text,file_path);
                                    adder.AddFile();

                                    res.getHeader().setStatus(201);
                                    res.getBody().put("text","Done!");
                                }else {
                                    res.getHeader().setStatus(403);
                                    res.getBody().put("text","Forbidden!!");
                                }

                                break;

                            }case ASymmetric:{
                                if(this.sessionKey != null){
                                    if(clientKey!= null && editPermission.get(clientKey).equals("ok")){
                                        text = decoder.decodeTextASymmetric(this.sessionKey);
                                        adder = new Adder(text,file_path);
                                        adder.AddFile();

                                        res.getHeader().setStatus(201);
                                        res.getBody().put("text","Done!");
                                    }else {
                                        res.getHeader().setStatus(403);
                                        res.getBody().put("text","Forbidden!!");
                                    }
                                }
                                break;
                            }
                            case None:{
                                text = (String) req.getBody().get("text");
                                adder = new Adder(text,file_path);
                                adder.AddFile();
                                break;
                            }
                        }
                        this.serverSocket.sendObject(res);
                        break;

                    }case DigitalSign:{
                         adder = new Adder(req,this.editPermission,this.serverKey,this.clientKey);
                         res= adder.doAdding();
                         this.serverSocket.sendObject(res);
                         break;

                    }
                    case File_certificate:{
                        adder = new Adder(req,this.editPermission,this.serverKey,this.clientKey,this.CAKey);
                        res = adder.doAdding();
                        this.serverSocket.sendObject(res);
                        break;
                    }
                    default:{

                    }
                 }
                 break;
                }

                case delete:{
                    System.out.println("deleting");
                   break;
                }
                default:{
                    res = new Response();
                    res.getHeader().setStatus(404);
                    res.getBody().put("msg","Not Found!!");
                    this.serverSocket.sendObject(res);

                }

            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

        @Override
    public void run() {
        try {
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();
            this.serverSocket = new ServerSocket(inputStream,outputStream);

            while (socket.isBound() && !socket.isClosed()){
                Request req = (Request)this.serverSocket.receiveObject();
                this.do_action(req);

            }
            }catch (IOException | ClassNotFoundException ignored){
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
}
