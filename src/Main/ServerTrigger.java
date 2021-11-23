package Main;

import serverSide.Server;

public class ServerTrigger {

    public static void main(String[] args){
        Server s= null;
        try {
            s = new Server(8080,"khaled");
            s.start();

        } catch (Exception e) {
            e.printStackTrace();
        }





    }
}
