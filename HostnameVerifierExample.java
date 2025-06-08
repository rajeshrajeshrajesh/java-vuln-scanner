import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
public class HostnameVerifierExample {
    public static void main(String[] args) {
        HostnameVerifier hv = (hostname, session) -> true;
    }
}