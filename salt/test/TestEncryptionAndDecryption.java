import logic.Encryptor;
import logic.IEncryption;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestEncryptionAndDecryption {

    String text1 = "This is a test text 1";
    String text2 = "This is another test text, wieeee....";
    String pass1 = "henk";
    String pass2 = "pass";

    @BeforeAll
    public static void beforeAll(){
        IEncryption encryptor = new Encryptor();

    }

    @Test
    public void TestEncryptionPositive(){

    }

    @Test
    public  void TestEncrytionNegative(){

    }
}
