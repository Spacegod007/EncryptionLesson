package logic;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class PasswordBasedEncryption {
    private static final String KEY_DERIVATION_FUNCTION = "PBKDF2WithHmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String GENERATOR_ALGORITHM = "SHA1PRNG";

    private static final int KEY_SIZE_IN_BITS = 128;
    private static final int TAG_SIZE_IN_BITS = 128;
    private static final int ITERATION_COUNT = 200_000;
    private static final int SALT_SIZE_IN_BITS = 1024;

    private PasswordBasedEncryption() {
    }

    static byte[] encrypt(byte[] message, char[] password) {
        try {
            byte[] salt = generateIV();
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, password, salt);
            byte[] ciphertext = cipher.doFinal(message);
            byte[] result = new byte[salt.length + ciphertext.length];
            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(ciphertext, 0, result, salt.length, ciphertext.length);

            return result;
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new AssertionError(ex);
        }
    }

    private static Cipher initCipher(int mode, char[] password, byte[] iv) {
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE_IN_BITS, iv);
        SecretKey key = deriveKey(password, iv);
        try {

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, key, gcmSpec);
            return cipher;
        } catch (
                NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new AssertionError(ex);
        } finally {
            try {
                key.destroy();
            }

            // Don't let exceptions escape from finally-blocks.
            catch (DestroyFailedException ex) {
            }
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_SIZE_IN_BITS);
        SecretKey pbeKey = null;
        byte[] keyBytes = null;

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_FUNCTION);
            pbeKey = factory.generateSecret(pbeKeySpec);

            keyBytes = pbeKey.getEncoded();
            return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
        } catch (
                NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new AssertionError(ex);
        } finally {
            try {
                pbeKeySpec.clearPassword();

                if (keyBytes != null)
                    Arrays.fill(keyBytes, (byte) 0);

                if (pbeKey != null && !pbeKey.isDestroyed())
                    pbeKey.destroy();
            } catch (DestroyFailedException ex) {
            }
        }
    }

    public static byte[] decryprion(byte[] encrypted, char[] password) {
        try {
            byte[] salt = Arrays.copyOfRange(encrypted, 0, SALT_SIZE_IN_BITS / 8);
            byte[] ciphertext = Arrays.copyOfRange(encrypted, salt.length, encrypted.length);

            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, password, salt);
            byte[] message = cipher.doFinal(ciphertext);

            return message;
        }

        // Block sizes are a property of block ciphers, not stream ciphers.
        catch (IllegalBlockSizeException ex) {
            throw new AssertionError(ex);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    private static byte[] generateIV() {
        try {
            SecureRandom random = SecureRandom.getInstance(GENERATOR_ALGORITHM);
            byte[] salt = new byte[SALT_SIZE_IN_BITS / 8];
            random.nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }
}
