package encryption;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyGenerator
{
    private static final Logger LOGGER = Logger.getLogger(KeyGenerator.class.getName());

    private static final String PUBLIC_KEY_FILE_EXTENSION = ".puk";
    private static final String PRIVATE_KEY_FILE_EXTENSION = ".prk";
    private static final String KEY_PAIR_ALGORITHM = "RSA";
    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

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
    }

    private KeyGenerator(String privateKeyLocation, String publicKeyLocation) throws NoSuchAlgorithmException
    {

        KeyPair keyPair = generateKeypair();

        try
        {
            Files.write(new File(publicKeyLocation + PUBLIC_KEY_FILE_EXTENSION).toPath(), keyPair.getPublic().getEncoded());
            Files.write(new File(privateKeyLocation + PRIVATE_KEY_FILE_EXTENSION).toPath(), keyPair.getPrivate().getEncoded());
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while interacting with the file", e);
        }
    }

    private KeyPair generateKeypair() throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_ALGORITHM);
        SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);

        keyPairGenerator.initialize(1024, random);
        return keyPairGenerator.generateKeyPair();
    }
/*

    */
}
