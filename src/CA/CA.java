package CA;

import java.io.Serializable;
import java.security.PublicKey;

public class CA implements Serializable {
    private PublicKey publicKey;
    private  String name ;

    public CA(PublicKey publicKey, String name) {
        this.publicKey = publicKey;
        this.name = name;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getName() {
        return name;
    }

}
