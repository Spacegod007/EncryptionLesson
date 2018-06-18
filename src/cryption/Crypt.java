package cryption;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

public abstract class Crypt
{
    protected static final Logger LOGGER = Logger.getLogger(Crypt.class.getName());

    protected static final String ALGORITHM = "RSA";
    protected static final String PROVIDER = "BC";
    protected static final String ENCRYPTION_STANDARD = "DES";

    private static final int DATA_OFFSET = 0;
    private static final int CIPHER_UPDATE_INTEGER_VALUE = 0;
    private static final int CIPHER_DO_FINAL_INTEGER_VALUE = 0;


    protected static void crypt(InputStream in, OutputStream out, Cipher cipher) throws IOException, GeneralSecurityException
    {
        int blockSize = cipher.getBlockSize();
        int outputSize = cipher.getOutputSize(blockSize);
        byte[] inBytes = new byte[blockSize];
        byte[] outBytes = new byte[outputSize];

        int inLength = 0;
        boolean more = true;

        while (more)
        {
            inLength = in.read(inBytes);
            if (inLength == blockSize)
            {
                int outLength = cipher.update(inBytes, CIPHER_UPDATE_INTEGER_VALUE, blockSize, outBytes);
                out.write(outBytes, DATA_OFFSET, outLength);
            } else more = false;
        }

        if (inLength > 0)
        {
            outBytes = cipher.doFinal(inBytes, CIPHER_DO_FINAL_INTEGER_VALUE, inLength);
        }
        else
        {
            outBytes = cipher.doFinal();
        }

        out.write(outBytes);
    }
}
