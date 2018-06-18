package encryption;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

public class Crypt
{


    private Crypt() {}

    private static final int DATA_OFFSET = 0;
    private static final int CIPHER_UPDATE_INTEGER_VALUE = 0;
    private static final int CIPHER_DOFINAL_INTEGER_VALUE = 0;


    public static void crypt(InputStream in, OutputStream out, Cipher cipher) throws IOException, GeneralSecurityException
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
            outBytes = cipher.doFinal(inBytes, CIPHER_DOFINAL_INTEGER_VALUE, inLength);
        }
        else
        {
            outBytes = cipher.doFinal();
        }

        out.write(outBytes);
    }
}
