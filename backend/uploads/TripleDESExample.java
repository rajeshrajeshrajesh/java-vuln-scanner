import javax.crypto.Cipher;
public class TripleDESExample {
    public static void main(String[] args) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }
}