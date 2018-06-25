package encryption;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyGenerator
{
    private static final Logger LOGGER = Logger.getLogger(KeyGenerator.class.getName());

    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static final int KEY_SIZE = 1024;

    /**
     *
     * @param args Argument 1: private key save location, Argument 2: public key save location
     */
    public static void main(String[] args)
    {
        try
        {
            new KeyGenerator(args[0], args[1]);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid algorithm detected!", e);
        }
        catch (InvalidKeySpecException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid key spec detected!", e);
        }
    }

    private KeyGenerator(String privateKeyLocation, String publicKeyLocation) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeyPair keyPair = generateKeypair();

//        PKCS8EncodedKeySpec keySpec = getPrivateKeySpec(keyPair.getPrivate());

//        writeKey(keyPair.getPrivate(), privateKeyLocation);
//        writeKey(keyPair.getPublic(), publicKeyLocation);

        try
        {
            Files.write(new File(publicKeyLocation).toPath(), keyPair.getPublic().getEncoded());
            Files.write(new File(privateKeyLocation).toPath(), keyPair.getPrivate().getEncoded());
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while interacting with the file", e);
        }
    }

    private void writeKey(Key key, String file)
    {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(new File(file))))
        {
            objectOutputStream.writeObject(key);
        }
        catch (FileNotFoundException e)
        {
            LOGGER.log(Level.SEVERE, "File could not be found", e);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while interacting with the file", e);
        }
    }

    private PKCS8EncodedKeySpec getPrivateKeySpec(PrivateKey key) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        KeyFactory factory = KeyFactory.getInstance(KeyValues.KEY_ALGORITHM);
        return factory.getKeySpec(key, PKCS8EncodedKeySpec.class);
    }

    private KeyPair generateKeypair() throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyValues.KEY_ALGORITHM);
        SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);

        keyPairGenerator.initialize(KEY_SIZE, random);
        return keyPairGenerator.generateKeyPair();
    }
}
