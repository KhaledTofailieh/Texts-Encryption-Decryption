package serverSide;

import CA.Certificate;
import Protocol.EncryptionWay;
import Protocol.Query;
import Protocol.Request;
import Protocol.Response;
import crypto.DigitalSignature;
import crypto.KeysGenerator;
import crypto.Symetric;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Getter {

    private KeyPair server_key;
    private String sessionKey;
    private Certificate certificate;

    Getter(KeyPair server_key,String sessionKey,Certificate certificate){
        this.server_key = server_key;
        this.sessionKey = sessionKey;
        this.certificate = certificate;

    }

    private String readFile(String file_path) throws IOException {
        System.out.println("file_path:  "+file_path);
        File myFile = new File(file_path);
        byte [] bytes;
        FileInputStream fis = new FileInputStream(myFile);
        BufferedInputStream bis = new BufferedInputStream(fis);


        bytes = bis.readAllBytes();
        return new String(bytes, Charset.defaultCharset());
    }

    public Response getResponse(Request request) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        Response res = new Response();

        switch ((Query)request.getParams().get("query")){
            case file:{
                String file_path = (String)request.getParams().get("file_path");
                try {
                    String text = readFile(file_path);
                    switch ((EncryptionWay)request.getParams().get("enc_way")){
                        case Symmetric:{
                            byte[] initVector =  KeysGenerator.createInitializationVector();
                            String s_init = Base64.getEncoder().encodeToString(initVector);
                            String cipher= Symetric.encrypt(text, initVector);

                            res.getHeader().setStatus(200);
                            res.getHeader().getParams().put("enc_way",EncryptionWay.Symmetric);
                            res.getBody().put("init_vec",s_init);
                            res.getBody().put("text",cipher);
                            break;
                        }
                        case ASymmetric:{
                           if(this.sessionKey != null){
                               res.getHeader().setStatus(200);
                               byte[] initVector =  KeysGenerator.createInitializationVector();
                               String init= Base64.getEncoder().encodeToString(initVector);
                               String cipher= Symetric.encrypt(text, initVector,sessionKey);

                               res.getHeader().getParams().put("enc_way",EncryptionWay.ASymmetric);
                               res.getBody().put("init_vec",init);
                               res.getBody().put("text",cipher);

                           }else{
                               res.getHeader().setStatus(403);
                               res.getBody().put("msg","Forbidden!!");

                           }
                           break;
                        }
                        case None:{
                              res.getHeader().setStatus(200);
                              res.getHeader().getParams().put("enc_way",EncryptionWay.None);
                              res.getBody().put("text",text);
                              break;
                        }
                        default:{
                            res.getHeader().setStatus(404);
                            res.getBody().put("msg","Not Found!!");
                        }
                    }

                } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                break;
            }

            case public_key:{
                res.getBody().put("public_key",this.server_key.getPublic());
                break;
            }case DigitalSign:{

                res.getHeader().setStatus(200);
                String file_path = (String)request.getParams().get("file_path");
                String text = readFile(file_path);
                byte[] hashMessage = DigitalSignature.getHashMessage(text);

                byte[] encryptedHash = DigitalSignature.encryptHashMessage(hashMessage,this.server_key.getPrivate());

                byte[] initVector =  KeysGenerator.createInitializationVector();
                String init= Base64.getEncoder().encodeToString(initVector);
                String encryptedMessage=Symetric.encrypt(text,initVector,this.sessionKey);

                res.getHeader().getParams().put("enc_way",EncryptionWay.ASymmetric);
                res.getBody().put("enc_hash",encryptedHash);
                res.getBody().put("text",encryptedMessage);
                res.getBody().put("init_vec",init);

                break;
            }case File_certificate:{
                String file_path = (String)request.getParams().get("file_path");
                String text = readFile(file_path);

                byte[] initVector =  KeysGenerator.createInitializationVector();
                String init= Base64.getEncoder().encodeToString(initVector);
                String encryptedMessage=Symetric.encrypt(text,initVector,this.sessionKey);

                res.getHeader().getParams().put("enc_way",EncryptionWay.ASymmetric);
                res.getBody().put("text",encryptedMessage);
                res.getBody().put("init_vec",init);
                res.getBody().put("certificate",this.certificate);
                break;

            }
            default:{
                break;
            }
        }
        return res;
    }
}
