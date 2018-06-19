package logic;

public interface IEncryption {
    void encryption(String message, char[] password);
    String decryption(char[] password);
}
