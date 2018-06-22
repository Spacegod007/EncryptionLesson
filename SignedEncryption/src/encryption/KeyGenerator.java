package encryption;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyGenerator
{
    private static final Logger LOGGER = Logger.getLogger(KeyGenerator.class.getName());

    private static final String PUBLIC_KEY_FILE_EXTENSION = ".pk";
    private static final String PRIVATE_KEY_FILE_EXTENSION = ".spk";
    private static final String ALGORITHM = "SHA512withRSA";
    private static final String KEY_PAIR_ALGORITHM = "RSA";
    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static final int DATA_OFFSET = 0;

    private final String dataLocation;
    private final String privateKeyLocation;

    public static void main(String[] args)
    {
        try
        {
            new KeyGenerator(args[0], args[1], args[2]);
        }
        catch (InvalidKeyException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid key detected!", e);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid algorithm detected!", e);
        }
        catch (SignatureException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while creating a signature", e);
        }
    }

    private KeyGenerator(String dataLocation, String privateKeyLocation, String publicKeyLocation) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException
    {
        this.dataLocation = dataLocation;
        this.privateKeyLocation = privateKeyLocation;

        KeyPair keyPair = generateKeypair();
        signKey(keyPair.getPrivate());

        try
        {
            Files.write(new File(publicKeyLocation + PUBLIC_KEY_FILE_EXTENSION).toPath(), keyPair.getPublic().getEncoded());
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

    private void signKey(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);

        try (FileInputStream fileInputStream = new FileInputStream(new File(dataLocation));
             InputStream inputStream = new BufferedInputStream(fileInputStream))
        {
            byte[] buffer = new byte[1024];

            int readByte;
            while ((readByte = inputStream.read(buffer)) >= 0)
            {
                signature.update(buffer, DATA_OFFSET, readByte);
            }

            Files.write(new File(privateKeyLocation + PRIVATE_KEY_FILE_EXTENSION).toPath(), signature.sign());
        }
        catch (FileNotFoundException e)
        {
            LOGGER.log(Level.WARNING, "File could not be found", e);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while interacting with the file", e);
        }
    }
}
