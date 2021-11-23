package crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class KeysGenerator {
    // Function to create a
    // secret key
    private static final String RSA = "RSA", AES="AES";

    public static SecretKey createKey() throws Exception {
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);

        keygenerator.init(256, securerandom);
        SecretKey key = keygenerator.generateKey();

        return key;
    }

    //Function to initialize a vector
    // with an arbitrary value
    public static byte[] createInitializationVector() {

        // Used with encryption
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }
    public static KeyPair generateKeyPair(int keySize)
            throws Exception
    {
        SecureRandom secureRandom
                = new SecureRandom();
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance(RSA);

        keyPairGenerator.initialize(
                keySize, secureRandom);
        return keyPairGenerator
                .generateKeyPair();
    }

}
