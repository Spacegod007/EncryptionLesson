package logic;

public interface IEncryption {
    byte[] encryption(String message, char[] password);
    byte[] decryprion(String path, char[] password);
}
