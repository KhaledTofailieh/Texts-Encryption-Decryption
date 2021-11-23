
package crypto;

// Java program to perform the
// encryption and decryption
// using asymmetric key


import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
//import javax.xml.bind
//        .DatatypeConverter;

public class ASymmetric {

    private static final String RSA
            = "RSA";
    private static Scanner sc;

    public static byte[] do_RSAEncryption(
            String plainText,
            PublicKey publicKey)
            throws Exception
    {
        Cipher cipher
                = Cipher.getInstance(RSA);

        cipher.init(
                Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(
                plainText.getBytes());
    }


    public static String do_RSADecryption(byte[] cipherText, PrivateKey privateKey) throws Exception
    {
        Cipher cipher
                = Cipher.getInstance(RSA);

        cipher.init(Cipher.DECRYPT_MODE,
                privateKey);
        byte[] result
                = cipher.doFinal(cipherText);

        return new String(result, StandardCharsets.UTF_8);
    }

    public static byte[] do_RSADecryption(byte[] cipherText, PublicKey publicKey) throws Exception
    {
        Cipher cipher
                = Cipher.getInstance(RSA);

        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        byte[] result = cipher.doFinal(cipherText);

        return result;
    }

}

