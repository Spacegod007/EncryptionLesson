package encryption;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;

import static encryption.Crypt.crypt;

public class Decrypt {
    public static void main(String[] args) {

        try (DataInputStream in = new DataInputStream(new FileInputStream(args[1]))) {
            int length = in.readInt();
            byte[] wrappedKey = new byte[length];
            in.read(wrappedKey, 0, length);

            // unwrap with RSA private key
            try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3]))) {
                Key privateKey = (Key) keyIn.readObject();

                Cipher cipher = Cipher.getInstance("RSA", "BC");
                cipher.init(Cipher.UNWRAP_MODE, privateKey);
                Key key = cipher.unwrap(wrappedKey, "DES", Cipher.SECRET_KEY);

                try (OutputStream out = new FileOutputStream(args[2])) {
                    cipher = Cipher.getInstance("DES", "BC");
                    cipher.init(Cipher.DECRYPT_MODE, key);

                    crypt(in, out, cipher);
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
