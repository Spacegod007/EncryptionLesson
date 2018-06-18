package encryption;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.logging.Level;

public class KeyGen extends Crypt
{
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) {
        try
        {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Crypt.ALGORITHM, Crypt.PROVIDER);
                SecureRandom random = new SecureRandom();
                keyPairGenerator.initialize(KEY_SIZE, random);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(args[0])))
                {
                    objectOutputStream.writeObject(keyPair.getPublic());
                }
                catch (IOException e)
                {
                    LOGGER.log(Level.SEVERE, "Something went wrong while writing the public key", e);
                }

                try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(args[1])))
                {
                    objectOutputStream.writeObject(keyPair.getPrivate());
                }
                catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Something went wrong while writing the private key", e);
                }
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.CONFIG, "Invalid algorithm selected", e);
        }
        catch (NoSuchProviderException e)
        {
            LOGGER.log(Level.CONFIG, "Invalid provider selected", e);
        }
    }
}