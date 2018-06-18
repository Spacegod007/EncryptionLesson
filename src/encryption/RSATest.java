package encryption;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class RSATest
{
    public static void main(String[] args)
    {
        try
        {
            if (args[0].equals("-genkey"))
            {
                KeyPairGenerator pairgen = KeyPairGenerator.getInstance("RSA", "BC");
                SecureRandom random = new SecureRandom();
                pairgen.initialize(KEYSIZE, random);
                KeyPair keyPair = pairgen.generateKeyPair();

                try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[1])))
                {
                    out.writeObject(keyPair.getPublic());
                }
                try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[2])))
                {
                    out.writeObject(keyPair.getPrivate());
                }
            }
            else if (args[0].equals("-encrypt"))
            {
                KeyGenerator keygen = KeyGenerator.getInstance("DES");
                SecureRandom random = new SecureRandom();
                keygen.init(random);
                SecretKey key = keygen.generateKey();

                // wrap with RSA public key
                try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3])))
                {
                    Key publicKey = (Key) keyIn.readObject();


                    Cipher cipher = Cipher.getInstance("RSA", "BC");
                    cipher.init(Cipher.WRAP_MODE, publicKey);
                    byte[] wrappedKey = cipher.wrap(key);
                    try (DataOutputStream out = new DataOutputStream(new FileOutputStream(args[2])))
                    {
                        out.writeInt(wrappedKey.length);
                        out.write(wrappedKey);

                        try (InputStream in = new FileInputStream(args[1]))
                        {
                            cipher = Cipher.getInstance("DES", "BC");
                            cipher.init(Cipher.ENCRYPT_MODE, key);
                            crypt(in, out, cipher);
                        }
                    }
                }
            }
            else
            {
                try (DataInputStream in = new DataInputStream(new FileInputStream(args[1])))
                {
                    int length = in.readInt();
                    byte[] wrappedKey = new byte[length];
                    in.read(wrappedKey, 0, length);

                    // unwrap with RSA private key
                    try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3])))
                    {
                        Key privateKey = (Key) keyIn.readObject();

                        Cipher cipher = Cipher.getInstance("RSA", "BC");
                        cipher.init(Cipher.UNWRAP_MODE, privateKey);
                        Key key = cipher.unwrap(wrappedKey, "DES", Cipher.SECRET_KEY);

                        try (OutputStream out = new FileOutputStream(args[2]))
                        {
                            cipher = Cipher.getInstance("DES", "BC");
                            cipher.init(Cipher.DECRYPT_MODE, key);

                            crypt(in, out, cipher);
                        }
                    }
                }
            }
        } catch (IOException exception)
        {
            exception.printStackTrace();
        } catch (GeneralSecurityException exception)
        {
            exception.printStackTrace();
        } catch (ClassNotFoundException exception)
        {
            exception.printStackTrace();
        }
    }


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
                int outLength
                        = cipher.update(inBytes, 0, blockSize, outBytes);
                        out.write(outBytes, 0, outLength);
            } else more = false;
        }
        if (inLength > 0)
            outBytes = cipher.doFinal(inBytes, 0, inLength);
        else
            outBytes = cipher.doFinal();
        out.write(outBytes);
    }

    public static final int KEYSIZE = 128;
}