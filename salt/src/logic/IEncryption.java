package logic;

public interface IEncryption {
    byte[] encryption(byte[] message, char[] password);

    byte[] decryprion(byte[] encrypted, char[] password);
}
