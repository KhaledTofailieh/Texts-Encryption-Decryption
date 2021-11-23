package serverSide;

import CA.Certificate;
import Protocol.EncryptionWay;
import Protocol.Query;
import Protocol.Request;
import Protocol.Response;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;

public class Adder {
    private String file_path;
    private String text;
    private Request request;
    private HashMap editPermissions;
    private KeyPair serverKeys;
    private PublicKey clientKey;
    private PublicKey CaKey;
    Adder(String text,String file_path){
        this.text=text;
        this.file_path= file_path;

    }

    public Adder(Request request, HashMap editPermissions,KeyPair serverKeys,PublicKey clientKey) {
        this.request = request;
        this.editPermissions = editPermissions;
        this.serverKeys = serverKeys;
        this.clientKey = clientKey;
    }

    public Adder(Request request, HashMap editPermissions,KeyPair serverKeys,PublicKey clientKey,PublicKey CAKey) {
        this.request = request;
        this.editPermissions = editPermissions;
        this.serverKeys = serverKeys;
        this.clientKey = clientKey;
        this.CaKey = CAKey;
    }

    public void AddFile(){
        //Base64.getDecoder().decode(this.text);
        byte[] bytes = text.getBytes();
        if(this.file_path ==null){
            this.file_path = this.generatePath();
        }

        try {
            this.writeFile(this.file_path, bytes);

            String ss = this.readFile(this.file_path);
            System.out.println(ss);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void AddFile(String text,String file_path){
        //byte[] bytes = Base64.getDecoder().decode(text);
        if(file_path ==null){
            file_path = this.generatePath();
        }
        try {
            this.writeFile(file_path, text.getBytes(Charset.defaultCharset()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeFile(String file_path, byte[] bytes) throws IOException {
        File myFile = new File(file_path);

        FileOutputStream fos = new FileOutputStream(myFile);
        BufferedOutputStream bis = new BufferedOutputStream(fos);

        bis.write(bytes);
        bis.close();
        fos.close();

    }

    private String readFile(String file_path) throws IOException {
        File myFile = new File(file_path);
        byte [] bytes;
        FileInputStream fis = new FileInputStream(myFile);
        BufferedInputStream bis = new BufferedInputStream(fis);


        bytes = bis.readAllBytes();
        return  new String(bytes, Charset.defaultCharset());
    }

    private String generatePath(){
        Date d = new Date();
       return String.valueOf(d.getTime());
    }

    public Response doAdding() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        Response response = new Response();
        Decoder decoder = new Decoder(request,this.serverKeys);
        Validation validation = new Validation(request,this.serverKeys);

        switch ((Query)request.getParams().get("query")){
            case DigitalSign:{
                 PublicKey pk1;
                 if(request.getParams().get("enc_way")==EncryptionWay.Symmetric || request.getParams().get("enc_way")== EncryptionWay.None){
                     pk1 = decoder.decodePublicKey();
                  }else{
                     pk1 = this.clientKey;
                  }
                String text = decoder.decodeTextSymmetric();
                if(editPermissions.get(Base64.getEncoder().encodeToString(pk1.getEncoded()))!= null){
                    if(validation.validateUser(pk1) && validation.validateText(text,pk1)){
                        AddFile(text,(String)request.getParams().get("file_path"));
                        response.getHeader().setStatus(201);
                        response.getBody().put("text","done");
                    }else{
                        response.getHeader().setStatus(403);
                        response.getBody().put("text","Forbidden!!");
                    }
                 }else{
                    response.getHeader().setStatus(403);
                    response.getBody().put("text","Forbidden!!");
                }
               break;
            }
            case File_certificate:{
                PublicKey pk1;

                if(request.getParams().get("enc_way")==EncryptionWay.Symmetric || request.getParams().get("enc_way")== EncryptionWay.None){
                    pk1 = decoder.decodePublicKey();
                }else{
                    pk1 = this.clientKey;
                }
                String text = decoder.decodeTextSymmetric();
                System.out.println("pk1:  ");
                System.out.println(pk1);
                if(editPermissions.get(Base64.getEncoder().encodeToString(pk1.getEncoded()))!= null){
                if(validation.validateCertificate((Certificate)request.getBody().get("certificate"),CaKey,pk1)){
                    AddFile(text,(String)request.getParams().get("file_path"));
                    response.getHeader().setStatus(201);
                    response.getBody().put("text","done");
                }else{
                    response.getHeader().setStatus(403);
                    response.getBody().put("text","Forbidden!!");
                }
                }
               break;
            }
            case file:{

            }
        }
        return response;
    }


}
