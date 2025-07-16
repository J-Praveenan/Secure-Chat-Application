package crypto;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

  private static final int AES_KEY_SIZE = 128;
  private static final int IV_SIZE = 12;
  public static final int TAG_SIZE = 128;

  // Generate a new AES key (128-bit)
  public static SecretKey generateAESKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(AES_KEY_SIZE);
    return keyGen.generateKey();
  }

  // Generate a random IV (12 bytes for AES)
  public static byte[] generateIV() {
    byte[] iv = new byte[IV_SIZE];
    new SecureRandom().nextBytes(iv);
    return iv;
  }

  // Encrypt plaintext using AES
  public static byte[] encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec paramSpec = new GCMParameterSpec(TAG_SIZE, iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    return cipher.doFinal(plaintext.getBytes("UTF-8"));
  }

  // Decrypt ciphertext using AES
  public static String decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec paramSpec = new GCMParameterSpec(TAG_SIZE, iv);
    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
    byte[] plaintextBytes = cipher.doFinal(ciphertext);
    return new String(plaintextBytes, "UTF-8");
  }

  // Convert byte[] back to SecretKey (used after decrypting with RSA)
  public static SecretKey keyFromBytes(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
  }

  // Base64 encode utility
  public static String encodeBase64(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }

  // Base64 decode utility
  public static byte[] decodeBase64(String base64) {
    return Base64.getDecoder().decode(base64);
  }
}
