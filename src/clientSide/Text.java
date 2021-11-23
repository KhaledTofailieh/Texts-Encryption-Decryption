package clientSide;

public class Text {
    public  static  String text1=" private void writeKeypair(String file_path) throws IOException {\n" +
            "        File f = new File(file_path);\n" +
            "        FileOutputStream fos = new FileOutputStream(f);\n" +
            "        ObjectOutputStream obs = new ObjectOutputStream(fos);\n" +
            "\n" +
            "        obs.writeObject(keyPair);\n" +
            "\n" +
            "    }\n" +
            "\n" +
            "    private KeyPair readKeypair(String file_path) throws IOException, ClassNotFoundException {\n" +
            "        File f = new File(file_path);\n" +
            "        FileInputStream fos = new FileInputStream(f);\n" +
            "        ObjectInputStream ios = new ObjectInputStream(fos);\n" +
            "\n" +
            "        return (KeyPair)ios.readObject();\n" +
            "\n" +
            "    }\n";


}
