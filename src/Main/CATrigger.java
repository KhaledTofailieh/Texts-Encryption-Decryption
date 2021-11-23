package Main;

import CA.CAServer;

public class CATgigger {
    public static void main(String [] args){
        try {
            CAServer ca = new CAServer("khaled_ca",9999);
            ca.start();
        } catch (Exception e) {
            System.out.println("Filed in CA Server Running");
        }
    }
}
