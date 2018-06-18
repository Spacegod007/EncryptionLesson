package encryption;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.util.logging.Level;

public class Encrypt extends Crypt
{
    public static void main(String[] args) throws NoSuchAlgorithmException
    {
        KeyGenerator keygen = KeyGenerator.getInstance(Crypt.ENCRYPTION_STANDARD);
        SecureRandom random = new SecureRandom();
        keygen.init(random);
        SecretKey key = keygen.generateKey();

        // wrap with RSA public key
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3])))
        {
            Key publicKey = (Key) keyIn.readObject();

            Cipher cipher = Cipher.getInstance(Crypt.ALGORITHM, Crypt.PROVIDER);
            cipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] wrappedKey = cipher.wrap(key);
            try (DataOutputStream out = new DataOutputStream(new FileOutputStream(args[2])))
            {
                out.writeInt(wrappedKey.length);
                out.write(wrappedKey);

                try (InputStream in = new FileInputStream(args[1]))
                {
                    cipher = Cipher.getInstance(Crypt.ENCRYPTION_STANDARD, Crypt.PROVIDER);
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    crypt(in, out, cipher);
                }
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
        catch (IllegalBlockSizeException e)
        {
            LOGGER.log(Level.CONFIG, "Invalid block size detected", e);
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
}
