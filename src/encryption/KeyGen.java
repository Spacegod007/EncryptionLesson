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
                KeyPairGenerator pairgen = KeyPairGenerator.getInstance(Crypt.ALGORITHM, Crypt.PROVIDER);
                SecureRandom random = new SecureRandom();
                pairgen.initialize(KEY_SIZE, random);
                KeyPair keyPair = pairgen.generateKeyPair();

                try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[1])))
                {
                    out.writeObject(keyPair.getPublic());
                }
                catch (IOException e)
                {
                    LOGGER.log(Level.SEVERE, "Something went wrong while writing the public key", e);
                }

                try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[2])))
                {
                    out.writeObject(keyPair.getPrivate());
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