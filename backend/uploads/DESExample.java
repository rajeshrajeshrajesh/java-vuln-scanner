import javax.crypto.Cipher;
public class DESExample {
    public static void main(String[] args) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}