package cryption.decryption;

import cryption.Crypt;

import javax.crypto.Cipher;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.logging.Level;

public class Decrypt extends Crypt
{
    private static final int DATA_OFFSET = 0;

    public static void main(String[] args)
    {
        try (DataInputStream dataInputStream = new DataInputStream(new FileInputStream(args[0])))
        {
            int length = dataInputStream.readInt();
            byte[] wrappedKey = new byte[length];
            //noinspection ResultOfMethodCallIgnored
            dataInputStream.read(wrappedKey, DATA_OFFSET, length);

            unwrapFile(args[2], wrappedKey, args[1], dataInputStream);
        }
        catch (FileNotFoundException e)
        {
            LOGGER.log(Level.WARNING, "Selected file was not found", e);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while interacting with a file", e);
        }
        catch (GeneralSecurityException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong in the security", e);
        }
        catch (ClassNotFoundException e)
        {
            LOGGER.log(Level.SEVERE, "Required class not found", e);
        }
    }

    private static void unwrapFile(String fileLocation, byte[] wrappedKey, String dataSaveLocation, DataInputStream dataInputStream) throws IOException, GeneralSecurityException, ClassNotFoundException
    {
        // unwrap with RSA private key
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(fileLocation)))
        {
            Key privateKey = (Key) objectInputStream.readObject();

            Cipher cipher = Cipher.getInstance(Crypt.ALGORITHM);
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            Key key = cipher.unwrap(wrappedKey, Crypt.ENCRYPTION_STANDARD, Cipher.SECRET_KEY);

            writeDecryptedData(dataSaveLocation, key, dataInputStream);
        }
    }

    private static void writeDecryptedData(String location, Key key, DataInputStream dataInputStream) throws IOException, GeneralSecurityException
    {
        try (OutputStream outputStream = new FileOutputStream(location))
        {
            Cipher cipher = Cipher.getInstance(Crypt.ENCRYPTION_STANDARD);
            cipher.init(Cipher.DECRYPT_MODE, key);

            crypt(dataInputStream, outputStream, cipher);
        }
    }
}
