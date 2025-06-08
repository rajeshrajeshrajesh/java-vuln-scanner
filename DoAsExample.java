import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
public class DoAsExample {
    public static void main(String[] args) throws Exception {
        Subject subject = new Subject();
        Subject.doAs(subject, (java.security.PrivilegedAction<Void>) () -> null);
    }
}