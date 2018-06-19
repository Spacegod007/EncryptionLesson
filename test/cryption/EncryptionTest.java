package cryption;

import cryption.decryption.Decrypt;
import cryption.encryption.Encrypt;
import cryption.keygeneration.KeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class EncryptionTest
{
    private static KeyGenerator keyGenerator;
    private static Decrypt decrypt;
    private static Encrypt encrypt;

    @BeforeAll
    public static void beforeAll()
    {
        keyGenerator = new KeyGenerator();
        decrypt = new Decrypt();
        encrypt = new Encrypt();
    }

    @BeforeEach
    public void beforeEach()
    {

    }

    @Test
    public void encryptionTest()
    {

    }
}
