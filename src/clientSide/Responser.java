package clientSide;

import CA.Certificate;
import Protocol.BadStatus;
import Protocol.EncryptionWay;
import Protocol.Response;
import crypto.DigitalSignature;
import crypto.Symetric;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public class Responser {
    private Response res;
    private SecretKey sessionKey;
    private PublicKey serverKey;

    public Responser(Response res, SecretKey sessionKey){
        this.res = res;
        this.sessionKey = sessionKey;
    }

    public  Responser(Response res, PublicKey serverKey){
        this.serverKey = serverKey;
        this.res= res;
    }
    public  Responser(Response res, PublicKey serverKey,SecretKey sessionKey){
        this.serverKey = serverKey;
        this.sessionKey = sessionKey;
        this.res= res;
    }
    public String getPlainText() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        int status = res.getHeader().getStatus();
        EncryptionWay enc = (EncryptionWay)res.getHeader().getParams().get("enc_way");
        String text =null;
        if(!BadStatus.inBads(status)){
            switch (enc){
                case Symmetric:{

                }case ASymmetric:{
                    if(!BadStatus.inBads(res.getHeader().getStatus())){
                        String cipher = (String) res.getBody().get("text");

                        String init =(String) res.getBody().get("init_vec");
                        text = Symetric.decrypt(cipher,init, Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
                        return text;
                    }else{
                        return (String)res.getBody().get("msg");
                    }
                }case None:{
                    return  (String) res.getBody().get("text");
                }
            }
        }
        return null;
    }

    public boolean certificateValidation(Certificate certificate,PublicKey CAPublic) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        byte[] serverKeyHash = DigitalSignature.getHashMessage(new String(this.serverKey.getEncoded(), Charset.defaultCharset()));

        byte [] decryptedServerKeyHash = DigitalSignature.decryptHashMessage(CAPublic,certificate.getServerKey());

        return DigitalSignature.compareHashMessages(serverKeyHash,decryptedServerKeyHash);
    }

}
