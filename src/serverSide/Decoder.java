package serverSide;

import Protocol.Request;
import crypto.ASymmetric;
import crypto.DigitalSignature;
import crypto.Symetric;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class Decoder {
    private Request request;



    Decoder(Request req, KeyPair server_key){
        this.request= req;
    }

    public String decodeSessionKey(PrivateKey privateKey) throws Exception {

        String s = (String) request.getBody().get("text");
        String sessionKey = ASymmetric.do_RSADecryption(Base64.getDecoder().decode(s),privateKey);
        return sessionKey;
    }

    public PublicKey decodePublicKey(){

        PublicKey ck = (PublicKey) request.getBody().get("public_key");
//        String s_ck = Base64.getEncoder().encodeToString(ck.getEncoded());

        return ck;
    }

    public String decodeTextSymmetric() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String text;
        String cipher = (String) request.getBody().get("text");
        String init =(String) request.getBody().get("init_vec");

        text = Symetric.decrypt(cipher,init);
        System.out.println("cipher "+cipher);
        System.out.println("text "+text);
        return text;
    }

    public String decodeTextASymmetric(String sessionKey) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String text;

        String cipher = (String) request.getBody().get("text");
        String init =(String) request.getBody().get("init_vec");

        text = Symetric.decrypt(cipher,init,sessionKey);

        return  text;
    }

    public byte[] decodeHashedPublicKey(PublicKey publicKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] encryptedHashPublic = (byte[])request.getBody().get("enc_hash_public");
        byte [] decryptedHashPublic= DigitalSignature.decryptHashMessage(publicKey,encryptedHashPublic);

        return  decryptedHashPublic;
    }

    public byte[] decodeHashedText(PublicKey publicKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] encryptedHashText = (byte[]) request.getBody().get("enc_hash_text");
        byte[] decryptedHashText = DigitalSignature.decryptHashMessage(publicKey,encryptedHashText);

        return decryptedHashText;
    }





}
