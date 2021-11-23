package CA;

import crypto.DigitalSignature;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.security.*;

public class Certificate  implements Serializable {
    private byte[] serverKey;
    private byte[] serverName;
    private String CAName;

    Certificate(KeyPair keys, PublicKey serverKey , String serverName,String CAName) throws NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        byte[] hashedServerKey = DigitalSignature.getHashMessage(new String(serverKey.getEncoded(), Charset.defaultCharset()));
        byte[] hashedServerName = DigitalSignature.getHashMessage(serverName);
        this.CAName = CAName;
        this.serverKey =DigitalSignature.encryptHashMessage(hashedServerKey,keys.getPrivate());
        this.serverName = DigitalSignature.encryptHashMessage(hashedServerName, keys.getPrivate());

    }

    public byte[] getServerKey() {
        return serverKey;
    }

    public byte[] getServerName() {
        return serverName;
    }

    public String getCAName(){
        return this.CAName;
    }

}
