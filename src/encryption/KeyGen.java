package encryption;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;

import static encryption.RSATest.KEYSIZE;

public class KeyGen {
    public static void main(String[] args) {
        try {
            if (args[0].equals("-genkey")) {
                KeyPairGenerator pairgen = KeyPairGenerator.getInstance("RSA", "BC");
                SecureRandom random = new SecureRandom();
                pairgen.initialize(KEYSIZE, random);
                KeyPair keyPair = pairgen.generateKeyPair();

                try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[1]))) {
                    out.writeObject(keyPair.getPublic());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[2]))) {
                    out.writeObject(keyPair.getPrivate());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }
}