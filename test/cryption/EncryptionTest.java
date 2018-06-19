package cryption;

import cryption.decryption.Decrypt;
import cryption.encryption.Encrypt;
import cryption.keygeneration.KeyGenerator;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class EncryptionTest
{
    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String ORIGINAL_TEST_FILE = "plaintextFile";
    private static final String ENCRYPTED_TEST_FILE = "encryptedFile";
    private static final String DECRYPTED_TEST_FILE = "decryptedFile";

    private static final Path ORIGINAL_TEST_FILE_PATH = new File(ORIGINAL_TEST_FILE).toPath();
    private static final Path ENCRYPTED_TEST_FILE_PATH = new File(ENCRYPTED_TEST_FILE).toPath();
    private static final Path DECRYPTED_TEST_FILE_PATH = new File(DECRYPTED_TEST_FILE).toPath();

    @Test
    public void fullTest() throws Exception
    {
        KeyGenerator.main(getAsArray(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE));
        Encrypt.main(getAsArray(ORIGINAL_TEST_FILE, ENCRYPTED_TEST_FILE, PUBLIC_KEY_FILE));
        Decrypt.main(getAsArray(ENCRYPTED_TEST_FILE, DECRYPTED_TEST_FILE, PRIVATE_KEY_FILE));

        assertFalse(Arrays.equals(Files.readAllBytes(ORIGINAL_TEST_FILE_PATH), Files.readAllBytes(ENCRYPTED_TEST_FILE_PATH)), "Contents of the encrypted file is equal to the original");
        assertArrayEquals(Files.readAllBytes(ORIGINAL_TEST_FILE_PATH), Files.readAllBytes(DECRYPTED_TEST_FILE_PATH), "Contents of the decrypted file is not equal to the original");
    }

    private String[] getAsArray(String ... strings)
    {
        return strings;
    }
}
