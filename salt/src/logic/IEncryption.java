package logic;

public interface IEncryption {
    void encryption(String message, char[] password);
    String decryprion(char[] password);
}
