package Main;

import clientSide.Client;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class ClientTrigger {
    private static int SERVER_PORT = 8080;
    private static String AbsoulatePath = "C:\\Users\\Khaled\\Desktop\\";
    public static void main(String[] args) {
        Client c = new Client("khaled","127.0.0.1",SERVER_PORT);
        Scanner scanner =  new Scanner(System.in);

while(true){
    System.out.println("Enter Name of file you want to process : ");
    String filename = scanner.nextLine();
    System.out.println("You want to do your action in Symmetric way [1]" +
            "\nYou want to do your action in PGP way [2]"+
            "\nYou want to do your action in Digital Sign [3]"+
            "\nYou want to do your action in Certificate [4]");
    String way = scanner.nextLine();
    System.out.println("You Want to view this File [1]" +
            "\nYou Want to edit this File [2]");
    String choise = scanner.nextLine();



    if(way.equals("1") && choise.equals("1")){
        String text = null;
        try {
            text = c.getFileSymmetricEncryption(AbsoulatePath+filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(text);

    }
    else if(way.equals("1") && choise.equals("2")){
        System.out.println("Enter Your text: ");
        String S = scanner.nextLine();
        try {
            String text = c.sendFileSymmetricEncryption(S,AbsoulatePath+filename);
            System.out.println(text);
        } catch (BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException | InvalidAlgorithmParameterException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

    }
    else if(way.equals("2") && choise.equals("1")){
        String text = null;
        try {
            text = c.getFileHybridEncryption(AbsoulatePath+filename);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(text);

    }
    else if(way.equals("2") && choise.equals("2")){
        System.out.println("Enter Your text: ");
        String S = scanner.nextLine();
        try {
            String text = c.sendFileHybridEncryption(S,AbsoulatePath+filename);
            System.out.println(text);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    if(way.equals("3") && choise.equals("1")){
        try {
            String text = c.getFileWithDigitalSignature(AbsoulatePath+filename);
            System.out.println(text);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }else if(way.equals("3")&& choise.equals("2")){
        String text = null;
        System.out.println("Enter Your text: ");
        String s = scanner.nextLine();
        try {
            text = c.sendTextDigitalSignatureSymmetric(s,AbsoulatePath+filename);

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(text);
    }else if(way.equals("4") && choise.equals("1")){
        String text = null;
//        System.out.println("Enter Your text: ");
//        String s = scanner.nextLine();
        try {
            text = c.getFileWithCertificate(AbsoulatePath+filename);

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(text);

    }
    else if(way.equals("4") && choise.equals("2")){
        String text = null;
        System.out.println("Enter Your text: ");
        String s = scanner.nextLine();
        try {
            text = c.sendTextWithCertificateSymmetric(s,AbsoulatePath+filename);

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(text);

    }




}
        //String text =c.getSymmetricEncryption("C:\\Users\\Khaled\\Desktop\\Django\\1.txt");
        //System.out.println(text);

        //String text2 = c.getFileHybridEncryption("C:\\Users\\Khaled\\Desktop\\Django\\1.txt");
        // System.out.println(text2);


        //c.sendFileSymmetricEncryption(Text.text1);

    }
}
