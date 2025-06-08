import java.security.Signature;
public class SHA1SignatureExample {
    public static void main(String[] args) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
    }
}