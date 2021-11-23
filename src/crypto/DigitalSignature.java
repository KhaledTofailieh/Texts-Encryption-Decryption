package crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Arrays;

public class DigitalSignature {
    public static byte[] encryptHashMessage(byte[] messageBytes, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] digitalSignature = cipher.doFinal(messageBytes);

        return digitalSignature;
    }

    public static byte[] decryptHashMessage(PublicKey publicKey, byte[] encryptedMessageHash) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedMessageHash = cipher.doFinal(encryptedMessageHash);

        return  decryptedMessageHash;
    }

    public static byte[] getHashMessage(String message) throws NoSuchAlgorithmException {
        byte [] messageBytes = message.getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(messageBytes);
        return messageHash;
    }

    public static boolean compareHashMessages(byte [] hash1, byte []hash2){
        return  Arrays.equals(hash1, hash2);
    }

}
