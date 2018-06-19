package logic;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Encryptor implements IEncryption
{
    private static final Logger LOGGER = Logger.getLogger(Encryptor.class.getName());
    private static final String FILE_LOCATION = "encrypted.file";

    @Override
    public void encryption(String message, char[] password)
    {
        byte[] encryptedData = PasswordBasedEncryption.encrypt(message.getBytes(), password);

        try
        {
            Files.write(new File(FILE_LOCATION).toPath(), encryptedData);
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while writing the encrypted data to the file");
        }
    }

    @Override
    public String decryption(char[] password)
    {
        byte[] encryptedData = new byte[0];

        try
        {
            encryptedData = Files.readAllBytes(new File(FILE_LOCATION).toPath());
        }
        catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while reading the encrypted data");
        }

        return new String(PasswordBasedEncryption.decryption(encryptedData, password));
    }
}
