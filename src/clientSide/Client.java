package clientSide;

import CA.CA;
import CA.Certificate;
import Protocol.*;
import crypto.ASymmetric;
import crypto.DigitalSignature;
import crypto.KeysGenerator;
import crypto.Symetric;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;

public class Client extends Thread {
    private KeyPair keyPair;
    private SecretKey sessionKey;
    private PublicKey serverKey;
    private ClientSocket clientSocket;
    private String clientName;
    private Certificate certificate;
    private HashMap CAs;

    public Client(String clientName,String server, int port)  {
        try {
            this.clientSocket = new ClientSocket(server,port);
            this.clientName= clientName;
            try {
                keyPair = this.clientSocket.readKeypair(clientName+".txt");
                System.out.println("load client keys>>");

            }catch (Exception e){
                keyPair = KeysGenerator.generateKeyPair(2048);
                this.clientSocket.writeKeypair(clientName+".txt",keyPair);
                System.out.println("create client keys>>");
            }
            try {
                CAs = (HashMap) this.clientSocket.readObject("cAs");
                System.out.println("load CAs>>");
            }catch (Exception e){
                CAs = new HashMap();
            }

            try {
                this.certificate = (Certificate) this.clientSocket.readObject(clientName+"_client_certificate");
                System.out.println("Load Server Certificate>>");
            }catch (FileNotFoundException e){
                System.out.println("Request Server Certificate>>");
                this.certificate = this.requestCertificate("127.0.0.1",9999);
                if(this.certificate!= null){
                    this.clientSocket.writeObject(clientName+"_client_certificate",this.certificate);
                }
            }

            this.serverKey = null;
            this.sessionKey= KeysGenerator.createKey();


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private Certificate requestCertificate(String CAUrl ,int port) {
        try {
            ClientSocket clientSocket = new ClientSocket(CAUrl,port);

            Request request = new Request(Methods.get, Query.Certificate);
            request.getBody().put("public",this.keyPair.getPublic());
            request.getBody().put("serverName",this.clientName);

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

    private void doHandChecking() throws Exception {
        Request req = new Request(Methods.add,Query.public_key);
        req.getBody().put("public_key",this.keyPair.getPublic());
        this.clientSocket.sendObject(req);


        Request req1 = new Request(Methods.get,Query.public_key);
        this.clientSocket.sendObject(req1);


        Response res1 = (Response) this.clientSocket.receiveObject();


        byte []cipherPublic;

        this.serverKey = (PublicKey) res1.getBody().get("public_key");
        cipherPublic = ASymmetric.do_RSAEncryption(Base64.getEncoder().encodeToString(sessionKey.getEncoded()),this.serverKey);
        String cipher_session = Base64.getEncoder().encodeToString(cipherPublic);

        Request req2 = new Request(Methods.add,Query.session_key);
        req2.getBody().put("text",cipher_session);
        this.clientSocket.sendObject(req2);

    }

    public String getFileWithoutEncryption(String name)  {
        String text = null;
        Request req = new Request(Methods.get,Query.file);
        Response res = null;
        try {
            this.clientSocket.sendObject(req);
        } catch (IOException e) {
            e.printStackTrace();
        }

        req.getParams().put("enc_way",EncryptionWay.None);
        req.getParams().put("file_path",name);
        try {
            res = (Response) this.clientSocket.receiveObject();

            text = (String) res.getBody().get("text");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        return text;
    }

    public String getFileSymmetricEncryption(String name) throws IOException {

        String text = null;
        Request req = new Request(Methods.get,Query.file);
        req.getParams().put("enc_way", EncryptionWay.Symmetric);
        req.getParams().put("file_path",name);

        this.clientSocket.sendObject(req);
        try {
            Response res = (Response) this.clientSocket.receiveObject();
            if(!BadStatus.inBads(res.getHeader().getStatus())){
                String cipher = (String) res.getBody().get("text");
                String init =(String) res.getBody().get("init_vec");
                text = Symetric.decrypt(cipher,init);
            }else {
                text = (String)res.getBody().get("text");
            }


        }catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return text;

    }

    public String getFileAsymmetricEncryption(String name){
     return null;
    }

    public String getFileHybridEncryption(String name) throws Exception {
        if(this.serverKey == null){
            this.doHandChecking();
        }
        Request req = new Request(Methods.get,Query.file);
        req.getParams().put("enc_way",EncryptionWay.ASymmetric);
        req.getParams().put("file_path",name);

        this.clientSocket.sendObject(req);

        Response res = (Response) this.clientSocket.receiveObject();
        if(!BadStatus.inBads(res.getHeader().getStatus())){
            String cipher = (String) res.getBody().get("text");
            String init =(String) res.getBody().get("init_vec");
            String text = Symetric.decrypt(cipher,init,Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
            return text;
        }else{
            return (String)res.getBody().get("msg");
        }
    }

    public String sendFileSymmetricEncryption(String text,String file_path) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, ClassNotFoundException {
        Request req = new Request(Methods.add,Query.file);
        req.getParams().put("enc_way",EncryptionWay.Symmetric);
        req.getParams().put("file_path",file_path);

        byte[] initVector =  KeysGenerator.createInitializationVector();
        String s_init = Base64.getEncoder().encodeToString(initVector);

        String cipher= Symetric.encrypt(text, initVector);
        String s_pk = Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded());

        req.getParams().put("pk",s_pk);
        req.getBody().put("init_vec",s_init);
        req.getBody().put("text",cipher);

        this.clientSocket.sendObject(req);

        Response res = (Response) this.clientSocket.receiveObject();
        String text1 = (String)res.getBody().get("text");

        return text1;
    }
    public String sendFileHybridEncryption(String text,String file_path) throws Exception {

        if(this.serverKey == null){
            this.doHandChecking();
        }
        Request req = new Request(Methods.add,Query.file);
        req.getParams().put("enc_way",EncryptionWay.ASymmetric);

        byte[] initVector =  KeysGenerator.createInitializationVector();
        String s_init = Base64.getEncoder().encodeToString(initVector);

        String cipher= Symetric.encrypt(text, initVector,Base64.getEncoder().encodeToString(this.sessionKey.getEncoded()));

        req.getBody().put("init_vec",s_init);
        req.getBody().put("text",cipher);
        req.getParams().put("file_path",file_path);

        this.clientSocket.sendObject(req);

        Response res = (Response) this.clientSocket.receiveObject();
        String text1 = (String)res.getBody().get("text");

        return text1;

    }
    public String getFileWithDigitalSignature(String file_path) throws Exception {
        if (serverKey == null){
            this.doHandChecking();
        }

        Request req = new Request(Methods.get,Query.DigitalSign);
        req.getParams().put("file_path",file_path);
        this.clientSocket.sendObject(req);

        Response res = (Response) this.clientSocket.receiveObject();

        Responser responser = new Responser(res,this.sessionKey);
        String text = responser.getPlainText();

        byte[] enc_hash= (byte[]) res.getBody().get("enc_hash");
//        System.out.println("enc_hash "+Base64.getEncoder().encodeToString(enc_hash));

        byte[] origin_hash= DigitalSignature.decryptHashMessage(this.serverKey,enc_hash);
//        System.out.println("origin_hash "+Base64.getEncoder().encodeToString(origin_hash));

//        System.out.println("text: "+text);
        byte[] new_hash = DigitalSignature.getHashMessage(text);
//        System.out.println(new String(new_hash,StandardCharsets.UTF_8));


        if(DigitalSignature.compareHashMessages(origin_hash,new_hash)){
            return text;
        }
        return "file has some mistake!!";
    }

    private PublicKey getCAKey(String ca_name){

      PublicKey ca_public = (PublicKey) CAs.get(ca_name);
      if(ca_public == null){
        CA ca = this.requestCA("127.0.0.1",9999);

        if (ca != null){
            this.CAs.put(ca.getName(),ca.getPublicKey());
            ca_public =  ca.getPublicKey();
        }
      }
      return  ca_public;
    }
    private CA requestCA(String CAUrl, int port) {
        CA ca  = null;
        try {
            ClientSocket cs = new ClientSocket(CAUrl, port);
            Request req = new Request(Methods.get, Query.public_key);
            cs.sendObject(req);

            Response res = (Response)cs.receiveObject();
            ca = (CA) res.getBody().get("ca");

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    return  ca;
    }
        public String getFileWithCertificate(String file_path) throws Exception {
        if(this.serverKey == null){
            this.doHandChecking();
        }


        Request request = new Request(Methods.get,Query.File_certificate);
        request.getParams().put("file_path",file_path);
        this.clientSocket.sendObject(request);

        Response res = (Response) this.clientSocket.receiveObject();

        Certificate certificate = (Certificate) res.getBody().get("certificate");
        PublicKey CaKey = this.getCAKey(certificate.getCAName());
        Responser responser = new Responser(res,this.serverKey,this.sessionKey);
        boolean cer_ok = responser.certificateValidation(certificate,CaKey);
        if(cer_ok){
            return  responser.getPlainText();
            }
        return  "this connection is not valid!!";

    }

    public String sendTextDigitalSignatureASymmetric(String text,String file_path) throws Exception {
        if(this.serverKey == null){
            this.doHandChecking();
        }

        Request request = new Request(Methods.add,Query.DigitalSign);
        request.getParams().put("file_path",file_path);

        byte[] hashPublicKey = DigitalSignature.getHashMessage(Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded()));
        byte[] hashText = DigitalSignature.getHashMessage(text);

        byte[] encryptedHashPublic = DigitalSignature.encryptHashMessage(hashPublicKey,this.keyPair.getPrivate());
        byte[] encryptedHashText = DigitalSignature.encryptHashMessage(hashText,this.keyPair.getPrivate());

        byte[] initVector =  KeysGenerator.createInitializationVector();
        String init= Base64.getEncoder().encodeToString(initVector);
        String encryptedMessage=Symetric.encrypt(text,initVector,Base64.getEncoder().encodeToString(this.sessionKey.getEncoded()));

        request.getParams().put("enc_way",EncryptionWay.ASymmetric);
        request.getBody().put("enc_hash_public",encryptedHashPublic);
        request.getBody().put("enc_hash_text",encryptedHashText);

        request.getBody().put("text",encryptedMessage);
        request.getBody().put("init_vec",init);

        this.clientSocket.sendObject(request);

        Response res = (Response)this.clientSocket.receiveObject();

        return (String) res.getBody().get("text");
    }

    public String sendTextDigitalSignatureSymmetric(String text,String file_path) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, ClassNotFoundException {

        Request request = new Request(Methods.add,Query.DigitalSign);

        request.getParams().put("file_path",file_path);

        byte[] hashPublicKey = DigitalSignature.getHashMessage(Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded()));
        byte[] hashText = DigitalSignature.getHashMessage(text);

        byte[] encryptedHashText = DigitalSignature.encryptHashMessage(hashText, this.keyPair.getPrivate());
        byte[] encryptedHashPublic = DigitalSignature.encryptHashMessage(hashPublicKey,this.keyPair.getPrivate());

        byte[] initVector =  KeysGenerator.createInitializationVector();
        String init= Base64.getEncoder().encodeToString(initVector);

        String encryptedMessage=Symetric.encrypt(text,initVector);

        request.getParams().put("enc_way",EncryptionWay.Symmetric);
        request.getBody().put("public_key",this.keyPair.getPublic());
        request.getBody().put("enc_hash_public",encryptedHashPublic);
        request.getBody().put("enc_hash_text",encryptedHashText);
        request.getBody().put("text",encryptedMessage);
        request.getBody().put("init_vec",init);

        this.clientSocket.sendObject(request);

        Response res = (Response)this.clientSocket.receiveObject();

        return (String) res.getBody().get("text");

    }

    public String sendTextWithCertificateSymmetric(String text,String file_path) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, ClassNotFoundException {
        Request request = new Request(Methods.add,Query.File_certificate);
        request.getParams().put("file_path",file_path);

        byte[] initVector =  KeysGenerator.createInitializationVector();
        String init= Base64.getEncoder().encodeToString(initVector);
        String encryptedMessage=Symetric.encrypt(text,initVector);

        request.getParams().put("enc_way",EncryptionWay.Symmetric);
        request.getBody().put("text",encryptedMessage);
        request.getBody().put("init_vec",init);
        request.getBody().put("certificate",this.certificate);
        request.getBody().put("public_key",this.keyPair.getPublic());

        this.clientSocket.sendObject(request);

        Response res = (Response)this.clientSocket.receiveObject();

        return (String) res.getBody().get("text");
    }

}
