package cryption.keygeneration;

import cryption.Crypt;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.logging.Level;

public class KeyGenerator extends Crypt
{
    private static final int KEY_SIZE = 1024;

    public static void main(String[] args)
    {
        try
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Crypt.ALGORITHM);
            SecureRandom random = new SecureRandom();
            keyPairGenerator.initialize(KEY_SIZE, random);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            writeKey(args[0], keyPair.getPublic());
            writeKey(args[1], keyPair.getPrivate());

        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid algorithm selected", e);
        }
    }

    private static void writeKey(String location, Key key)
    {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(location)))
        {
            objectOutputStream.writeObject(key);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while writing the private key", e);
        }
    }
}