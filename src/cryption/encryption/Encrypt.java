package cryption.encryption;

import cryption.Crypt;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.util.logging.Level;

public class Encrypt extends Crypt
{
    public static void main(String[] args) throws NoSuchAlgorithmException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(Crypt.ENCRYPTION_STANDARD);
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();

        // wrap with RSA public secretKey
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[2])))
        {
            Key publicKey = (Key) keyIn.readObject();

            Cipher cipher = Cipher.getInstance(Crypt.ALGORITHM, Crypt.PROVIDER);
            cipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] wrappedKey = cipher.wrap(secretKey);

            writeFileContents(args[1], wrappedKey, args[0], secretKey);
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
            LOGGER.log(Level.SEVERE, "Attempted to use invalid secretKey", e);
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

    private static void writeFileContents(String outputLocation, byte[] wrappedKey, String inputLocation, SecretKey secretKey) throws IOException, GeneralSecurityException
    {
        try (DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(outputLocation)))
        {
            dataOutputStream.writeInt(wrappedKey.length);
            dataOutputStream.write(wrappedKey);

            cryptData(inputLocation, dataOutputStream, secretKey);
        }
    }

    private static void cryptData(String fileLocation, DataOutputStream dataOutputStream, SecretKey secretKey) throws IOException, GeneralSecurityException
    {
        try (InputStream inputStream = new FileInputStream(fileLocation))
        {
            Cipher cipher = Cipher.getInstance(Crypt.ENCRYPTION_STANDARD, Crypt.PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            crypt(inputStream, dataOutputStream, cipher);
        }
    }
}
