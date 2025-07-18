package crypto;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for AES encryption/decryption using AES-GCM mode.
 */
public class AESUtil {

  private static final int AES_KEY_SIZE = 128;      // AES-128
  private static final int IV_SIZE = 12;            // 96-bit IV recommended for GCM
  public static final int TAG_SIZE = 128;           // 128-bit authentication tag

  /**
   * Generates a new AES-128 key.
   * @return SecretKey instance
   * @throws Exception if key generation fails
   */
  public static SecretKey generateAESKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(AES_KEY_SIZE);
    return keyGen.generateKey();
  }

  /**
   * Generates a random 12-byte IV suitable for AES-GCM.
   * @return Byte array of IV
   */
  public static byte[] generateIV() {
    byte[] iv = new byte[IV_SIZE];
    new SecureRandom().nextBytes(iv);
    return iv;
  }

  /**
   * Encrypts plaintext using AES-GCM with provided key and IV.
   * @param plaintext The string to encrypt
   * @param key AES secret key
   * @param iv Initialization vector (12 bytes recommended)
   * @return Encrypted ciphertext as byte array
   * @throws Exception if encryption fails
   */
  public static byte[] encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec paramSpec = new GCMParameterSpec(TAG_SIZE, iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    return cipher.doFinal(plaintext.getBytes("UTF-8"));
  }

  /**
   * Decrypts AES-GCM encrypted ciphertext.
   * @param ciphertext The encrypted byte array
   * @param key AES secret key
   * @param iv Initialization vector used for encryption
   * @return Decrypted plaintext string
   * @throws Exception if decryption fails or tag verification fails
   */
  public static String decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec paramSpec = new GCMParameterSpec(TAG_SIZE, iv);
    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
    byte[] plaintextBytes = cipher.doFinal(ciphertext);
    return new String(plaintextBytes, "UTF-8");
  }

  /**
   * Reconstructs a SecretKey from raw byte data (e.g., after decryption from RSA).
   * @param keyBytes Byte array containing raw AES key
   * @return SecretKey instance
   */
  public static SecretKey keyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
  }

  /**
   * Encodes a byte array to Base64 string.
   * @param data Byte array to encode
   * @return Base64 string
   */
  public static String encodeBase64(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }

  /**
   * Decodes a Base64 string to byte array.
   * @param base64 Base64 encoded string
   * @return Decoded byte array
   */
  public static byte[] decodeBase64(String base64) {
    return Base64.getDecoder().decode(base64);
  }
}
