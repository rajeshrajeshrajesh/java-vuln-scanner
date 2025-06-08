import java.security.SecureRandom;
public class SecureRandomExample {
    public static void main(String[] args) {
        SecureRandom sr = new SecureRandom(new byte[]{1, 2, 3});
    }
}