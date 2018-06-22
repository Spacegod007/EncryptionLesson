package encryption;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeySigner
{
    private static final Logger LOGGER = Logger.getLogger(KeySigner.class.getName());

    private static final String ALGORITHM = "SHA512withRSA";
    private static final int DATA_OFFSET = 0;
    private static final String KEY_ALGORITHM = "RSA";

    private final String privateKeyLocation;
    private final String dataLocation;

    public static void main(String[] args)
    {
        try
        {
            new KeySigner(args[0], args[1]);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid algorithm specified", e);
        }
        catch (SignatureException e)
        {
            LOGGER.log(Level.SEVERE, "An error occurred while signing the key", e);
        }
        catch (InvalidKeyException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid key specified", e);
        }
        catch (InvalidKeySpecException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid key spec specified", e);
        }
    }

    private KeySigner(String privateKeyLocation, String dataLocation) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException
    {
        this.privateKeyLocation = privateKeyLocation;
        this.dataLocation = dataLocation;

        PrivateKey privateKey = null;

        try
        {
            privateKey = retrieveEncodedPrivateKey();
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while reading the private key data");
        }

        if (privateKey != null)
        {
            signKey(privateKey);
        }
    }

    private PrivateKey retrieveEncodedPrivateKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException
    {
        byte[] bytes = Files.readAllBytes(new File(privateKeyLocation).toPath());
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(bytes));

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

            Files.write(new File(privateKeyLocation).toPath(), signature.sign());
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
