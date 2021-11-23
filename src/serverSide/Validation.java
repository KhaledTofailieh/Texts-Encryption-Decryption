package serverSide;

import CA.Certificate;
import Protocol.Request;
import crypto.DigitalSignature;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public class Validation {
    private Request request;
    private KeyPair serverKeys;
    public Validation(Request request,KeyPair serverKeys) {
        this.request = request;
        this.serverKeys = serverKeys;
    }

    public boolean validateUser(PublicKey public_key) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        Decoder decoder = new Decoder(request,serverKeys);
        byte [] hashedPublicKey1 = DigitalSignature.getHashMessage(Base64.getEncoder().encodeToString(public_key.getEncoded()));
        byte [] hashedPublicKey2 = decoder.decodeHashedPublicKey(public_key);

        return DigitalSignature.compareHashMessages(hashedPublicKey1,hashedPublicKey2);
    }

    public boolean validateText(String text,PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        Decoder decoder = new Decoder(request,serverKeys);
        byte [] hashedText1 = DigitalSignature.getHashMessage(text);
        byte [] hashedText2 = decoder.decodeHashedText(publicKey);

        return  DigitalSignature.compareHashMessages(hashedText1,hashedText2);
    }

    public boolean validateCertificate(Certificate certificate,  PublicKey caKey,PublicKey clientKey) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        byte[] clientKeyHash = DigitalSignature.getHashMessage(new String(clientKey.getEncoded(), Charset.defaultCharset()));

        byte [] decryptedClientKeyHash = DigitalSignature.decryptHashMessage(caKey,certificate.getServerKey());

        return DigitalSignature.compareHashMessages(clientKeyHash,decryptedClientKeyHash);
    }

}
