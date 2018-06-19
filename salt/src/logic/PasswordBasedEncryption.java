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
import java.util.logging.Level;
import java.util.logging.Logger;

class PasswordBasedEncryption
{
    private static final Logger LOGGER = Logger.getLogger(PasswordBasedEncryption.class.getName());
    private static final String KEY_DERIVATION_FUNCTION = "PBKDF2WithHmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String GENERATOR_ALGORITHM = "SHA1PRNG";

    private static final int KEY_SIZE_IN_BITS = 128;
    private static final int TAG_SIZE_IN_BITS = 128;
    private static final int ITERATION_COUNT = 200_000;
    private static final int SALT_SIZE_IN_BITS = 1024;

    private PasswordBasedEncryption()
    {
    }

    static byte[] encrypt(byte[] message, char[] password)
    {
        try
        {
            byte[] salt = generateIV();
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, password, salt);
            byte[] cipherText = cipher.doFinal(message);
            byte[] result = new byte[salt.length + cipherText.length];
            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(cipherText, 0, result, salt.length, cipherText.length);

            return result;
        } catch (IllegalBlockSizeException | BadPaddingException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while encrypting the data", e);
            throw new AssertionError(e);
        }
    }

    private static Cipher initCipher(int mode, char[] password, byte[] iv)
    {
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE_IN_BITS, iv);
        SecretKey key = deriveKey(password, iv);
        try
        {

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, key, gcmSpec);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e)
        {
            LOGGER.log(Level.SEVERE, "Something went wrong while initiating cipher", e);
            throw new AssertionError(e);
        } finally
        {
            try
            {
                key.destroy();
            } catch (DestroyFailedException e)
            {
                LOGGER.log(Level.SEVERE, "Failed to destroy the key", e);
            }
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt)
    {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_SIZE_IN_BITS);
        SecretKey pbeKey = null;
        byte[] keyBytes = null;

        try
        {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_FUNCTION);
            pbeKey = factory.generateSecret(pbeKeySpec);

            keyBytes = pbeKey.getEncoded();
            return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
        } catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.SEVERE, "Algorithm not found", e);
            throw new AssertionError(e);
        } catch (InvalidKeySpecException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid key spec specified", e);
            throw new AssertionError(e);
        } finally
        {
            try
            {
                pbeKeySpec.clearPassword();

                if (keyBytes != null)
                {
                    Arrays.fill(keyBytes, (byte) 0);
                }

                if (pbeKey != null && !pbeKey.isDestroyed())
                {
                    pbeKey.destroy();
                }
            } catch (DestroyFailedException e)
            {
                LOGGER.log(Level.SEVERE, "Failed to destroy key", e);
            }
        }
    }

    static byte[] decryption(byte[] encrypted, char[] password)
    {
        try
        {
            byte[] salt = Arrays.copyOfRange(encrypted, 0, SALT_SIZE_IN_BITS / 8);
            byte[] cipherText = Arrays.copyOfRange(encrypted, salt.length, encrypted.length);

            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, password, salt);
            return cipher.doFinal(cipherText);
        } catch (IllegalBlockSizeException e)
        {
            LOGGER.log(Level.SEVERE, "Illegal block size specified", e);
            throw new AssertionError(e);
        } catch (BadPaddingException e)
        {
            LOGGER.log(Level.SEVERE, "Padding failed", e);
        }
        return new byte[0];
    }

    private static byte[] generateIV()
    {
        try
        {
            SecureRandom random = SecureRandom.getInstance(GENERATOR_ALGORITHM);
            byte[] salt = new byte[SALT_SIZE_IN_BITS / 8];
            random.nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException e)
        {
            LOGGER.log(Level.SEVERE, "Invalid algorithm specified", e);
        }
        return new byte[0];
    }
}
