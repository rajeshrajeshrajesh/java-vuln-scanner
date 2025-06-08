import javax.crypto.Cipher;
import javax.crypto.NullCipher;
import java.security.SecureRandom;

public class Example {
    public static void main(String[] args) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecureRandom sr = new SecureRandom(new byte[]{1,2,3});
        System.setProperty("javax.net.debug", "all");
        String password = "secret123";
    }
}
