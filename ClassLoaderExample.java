public class ClassLoaderExample {
    public static void main(String[] args) throws Exception {
        ClassLoader cl = ClassLoader.getSystemClassLoader();
        cl.loadClass("java.lang.String");
    }
}