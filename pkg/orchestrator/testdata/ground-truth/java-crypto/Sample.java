import javax.crypto.Cipher;

public class Sample {
    public static final int KEY_SIZE = 256;

    public void encrypt() {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] key = new byte[KEY_SIZE / 8];
    }
}
