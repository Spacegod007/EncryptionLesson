package encryption;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
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
            dataInputStream.read(wrappedKey, DATA_OFFSET, length);

            // unwrap with RSA private key
            try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(args[2])))
            {
                Key privateKey = (Key) objectInputStream.readObject();

                Cipher cipher = Cipher.getInstance(Crypt.ALGORITHM, Crypt.PROVIDER);
                cipher.init(Cipher.UNWRAP_MODE, privateKey);
                Key key = cipher.unwrap(wrappedKey, Crypt.ENCRYPTION_STANDARD, Cipher.SECRET_KEY);

                try (OutputStream outputStream = new FileOutputStream(args[1]))
                {
                    cipher = Cipher.getInstance(Crypt.ENCRYPTION_STANDARD, Crypt.PROVIDER);
                    cipher.init(Cipher.DECRYPT_MODE, key);

                    crypt(dataInputStream, outputStream, cipher);
                }
            }
            catch (NoSuchAlgorithmException e)
            {
                LOGGER.log(Level.CONFIG, "Invalid algorithm selected", e);
            }
            catch (InvalidKeyException e)
            {
                LOGGER.log(Level.SEVERE, "Attempted to use invalid key", e);
            }
            catch (NoSuchPaddingException e)
            {
                LOGGER.log(Level.WARNING, "Error with padding", e);
            }
            catch (NoSuchProviderException e)
            {
                LOGGER.log(Level.CONFIG, "Invalid provider selected", e);
            }
            catch (GeneralSecurityException e)
            {
                LOGGER.log(Level.SEVERE, "Something went wrong dataInputStream the security", e);
            }
            catch (ClassNotFoundException e)
            {
                LOGGER.log(Level.SEVERE, "Required class not found", e);
            }
        }
        catch (FileNotFoundException e)
        {
            LOGGER.log(Level.WARNING, "Selected file was not found", e);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while interacting with a file", e);
        }
    }
}
