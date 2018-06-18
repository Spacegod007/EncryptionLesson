package encryption;

import javax.crypto.*;
import java.io.*;
import java.security.*;

import static encryption.Crypt.crypt;

public class Encrypt {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        if (args[0].equals("-encrypt")) {
            KeyGenerator keygen = KeyGenerator.getInstance("DES");
            SecureRandom random = new SecureRandom();
            keygen.init(random);
            SecretKey key = keygen.generateKey();

            // wrap with RSA public key
            try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3]))) {
                Key publicKey = (Key) keyIn.readObject();


                Cipher cipher = Cipher.getInstance("RSA", "BC");
                cipher.init(Cipher.WRAP_MODE, publicKey);
                byte[] wrappedKey = cipher.wrap(key);
                try (DataOutputStream out = new DataOutputStream(new FileOutputStream(args[2]))) {
                    out.writeInt(wrappedKey.length);
                    out.write(wrappedKey);

                    try (InputStream in = new FileInputStream(args[1])) {
                        cipher = Cipher.getInstance("DES", "BC");
                        cipher.init(Cipher.ENCRYPT_MODE, key);
                        crypt(in, out, cipher);
                    }
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
}
