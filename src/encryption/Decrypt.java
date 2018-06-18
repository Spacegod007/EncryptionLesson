package encryption;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.util.logging.Level;

public class Decrypt extends Crypt
{
    public static void main(String[] args)
    {
        try (DataInputStream in = new DataInputStream(new FileInputStream(args[1])))
        {
            int length = in.readInt();
            byte[] wrappedKey = new byte[length];
            in.read(wrappedKey, 0, length);

            // unwrap with RSA private key
            try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3])))
            {
                Key privateKey = (Key) keyIn.readObject();

                Cipher cipher = Cipher.getInstance(Crypt.ALGORITHM, Crypt.PROVIDER);
                cipher.init(Cipher.UNWRAP_MODE, privateKey);
                Key key = cipher.unwrap(wrappedKey, Crypt.ENCRYPTION_STANDARD, Cipher.SECRET_KEY);

                try (OutputStream out = new FileOutputStream(args[2]))
                {
                    cipher = Cipher.getInstance(Crypt.ENCRYPTION_STANDARD, Crypt.PROVIDER);
                    cipher.init(Cipher.DECRYPT_MODE, key);

                    crypt(in, out, cipher);
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
                LOGGER.log(Level.SEVERE, "Something went wrong in the security", e);
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
