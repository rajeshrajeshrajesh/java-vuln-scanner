import java.security.AccessController;
public class DoPrivilegedExample {
    public static void main(String[] args) {
        AccessController.doPrivileged(() -> {});
    }
}