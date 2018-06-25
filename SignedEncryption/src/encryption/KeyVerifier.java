package encryption;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyVerifier
{
    private static final Logger LOGGER = Logger.getLogger(KeyVerifier.class.getName());

    private static final int DATA_OFFSET = 0;

    private final String encryptedDataLocation;
    private final String saveDataLocation;
    private final String keyLocation;

    public static void main(String[] args)
    {
        try
        {
            new KeyVerifier(args[0], args[1], args[2]);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid algorithm specified", e);
        }
        catch (InvalidKeySpecException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid key spec specified", e);
        }
        catch (InvalidKeyException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid key specified", e);
        }
        catch (SignatureException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while verifying the signature", e);
        }
    }

    private KeyVerifier(String encryptedDataLocation, String saveDataLocation, String keyLocation) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException
    {
        this.encryptedDataLocation = encryptedDataLocation;
        this.saveDataLocation = saveDataLocation;
        this.keyLocation = keyLocation;

        PublicKey publicKey;

        try
        {
            publicKey = getPublicKey();
            decodeAndWriteEncryptedData(verifyPublicKey(publicKey));
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while interacting with key file", e);
        }
    }

    private void decodeAndWriteEncryptedData(Signature signature) throws IOException, SignatureException
    {
        boolean verified = false;

        try (FileInputStream fileInputStream = new FileInputStream(encryptedDataLocation);
             BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
             OutputStream outputStream = new FileOutputStream(saveDataLocation);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream))
        {
            int signatureByteLength = fileInputStream.read();
            byte[] signatureByte = new byte[signatureByteLength];
            fileInputStream.read(signatureByte);

            byte[] buffer = new byte[1024];
            while (bufferedInputStream.available() != 0)
            {
                int part = bufferedInputStream.read(buffer);
                bufferedOutputStream.write(buffer, DATA_OFFSET, part);
                signature.update(buffer, DATA_OFFSET, part);
            }

            verified = signature.verify(signatureByte);
        }

        String infoMessage = "Verification status: " + verified;
        LOGGER.log(Level.INFO, infoMessage);
    }

    private Signature verifyPublicKey(PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException
    {
        Signature signature = Signature.getInstance(KeyValues.SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        return signature;
    }

    private PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        byte[] keyBytes = Files.readAllBytes(new File(keyLocation).toPath());
        KeyFactory keyFactory = KeyFactory.getInstance(KeyValues.KEY_ALGORITHM);
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }


}
