package cryption.keygeneration;

import cryption.Crypt;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.logging.Level;

public class KeyGenerator extends Crypt
{
    private static final int KEY_SIZE = 128;

    public static void main(String[] args)
    {
        try
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Crypt.ALGORITHM, Crypt.PROVIDER);
            SecureRandom random = new SecureRandom();
            keyPairGenerator.initialize(KEY_SIZE, random);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            writePublicKey(args[0], keyPair.getPublic());
            writePrivateKey(args[1], keyPair.getPrivate());

        } catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.CONFIG, "Invalid algorithm selected", e);
        } catch (NoSuchProviderException e)
        {
            LOGGER.log(Level.CONFIG, "Invalid provider selected", e);
        }
    }

    private static void writePrivateKey(String location, PrivateKey privateKey)
    {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(location)))
        {
            objectOutputStream.writeObject(privateKey);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while writing the private key", e);
        }
    }

    private static void writePublicKey(String location, PublicKey publicKey)
    {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(location)))
        {
            objectOutputStream.writeObject(publicKey);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while writing the public key", e);
        }
    }
}