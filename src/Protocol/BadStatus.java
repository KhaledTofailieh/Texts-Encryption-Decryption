package Protocol;

public class
BadStatus {
   // private static int [] bads;

//    public int[] getBads() {
//        return bads;
//    }
    public static boolean inBads(int status){
        return status>=400;
    }
}
