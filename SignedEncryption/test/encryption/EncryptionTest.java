package encryption;

import org.junit.jupiter.api.Test;

public class EncryptionTest
{
    private static final String DATA_FILE_LOCATION = "data.file";
    private static final String ENCRYPTED_DATA_FILE_LOCATION = "generated_data.file";
    private static final String DECRYPTED_DATA_FILE_LOCATION = "decrypt.file";
    private static final String PRIVATE_KEY_LOCATION = "private";
    private static final String PUBLIC_KEY_LOCATION = "public";


    @Test
    public void fullTest()
    {
        KeyGenerator.main(getAsArray(PRIVATE_KEY_LOCATION, PUBLIC_KEY_LOCATION));
        KeySigner.main(getAsArray(DATA_FILE_LOCATION, ENCRYPTED_DATA_FILE_LOCATION, PRIVATE_KEY_LOCATION));
        KeyVerifier.main(getAsArray(ENCRYPTED_DATA_FILE_LOCATION, DECRYPTED_DATA_FILE_LOCATION, PUBLIC_KEY_LOCATION));
    }

    private String[] getAsArray(String ... strings)
    {
        return strings;
    }
}
