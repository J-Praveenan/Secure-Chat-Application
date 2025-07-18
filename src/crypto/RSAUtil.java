package crypto;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSAUtil {

  private static final int KEY_SIZE = 2048;

  /**
   * Generates a new RSA key pair.
   * @return KeyPair containing both private and public keys.
   */
  public static KeyPair generateKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(KEY_SIZE);
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new RuntimeException("RSA Key Generation Failed", e);
    }
  }

  /**
   * Encodes a PublicKey to a Base64 string.
   * @param pubKey The public key to encode.
   * @return Base64 string representation of the public key.
   */
  public static String getBase64PublicKey(PublicKey pubKey) {
    return Base64.getEncoder().encodeToString(pubKey.getEncoded());
  }

  /**
   * Encodes a PrivateKey to a Base64 string.
   * @param privKey The private key to encode.
   * @return Base64 string representation of the private key.
   */
  public static String getBase64PrivateKey(PrivateKey privKey) {
    return Base64.getEncoder().encodeToString(privKey.getEncoded());
  }

  /**
   * Decodes a Base64-encoded public key string into a PublicKey object.
   * @param base64Key The Base64 public key string.
   * @return PublicKey instance.
   */
  public static PublicKey getPublicKeyFromBase64(String base64Key) {
    try {
      byte[] bytes = Base64.getDecoder().decode(base64Key);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      return factory.generatePublic(spec);
    } catch (Exception e) {
      throw new RuntimeException("Invalid public key", e);
    }
  }

  /**
   * Decodes a Base64-encoded private key string into a PrivateKey object.
   * @param base64Key The Base64 private key string.
   * @return PrivateKey instance.
   */
  public static PrivateKey getPrivateKeyFromBase64(String base64Key) {
    try {
      byte[] bytes = Base64.getDecoder().decode(base64Key);
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      return factory.generatePrivate(spec);
    } catch (Exception e) {
      throw new RuntimeException("Invalid Base64 private key", e);
    }
  }

  /**
   * Encrypts data using an RSA public key.
   * @param data The plaintext bytes to encrypt.
   * @param publicKey The recipient's public key.
   * @return Encrypted byte array.
   */
  public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(data);
  }

  /**
   * Decrypts data using an RSA private key.
   * @param encryptedData The encrypted byte array.
   * @param privateKey The private key to decrypt with.
   * @return Decrypted byte array.
   */
  public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return cipher.doFinal(encryptedData);
  }

  /**
   * Signs a string message using a private RSA key.
   * @param data The message to sign.
   * @param privateKey The private key for signing.
   * @return Digital signature as a byte array.
   */
  public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data.getBytes());
    return signature.sign();
  }

  /**
   * Verifies a digital signature using the corresponding RSA public key.
   * @param data The original message.
   * @param signatureBytes The signature to verify.
   * @param publicKey The public key to verify against.
   * @return true if the signature is valid, false otherwise.
   */
  public static boolean verify(String data, byte[] signatureBytes, PublicKey publicKey) {
    try {
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(publicKey);
      signature.update(data.getBytes());
      return signature.verify(signatureBytes);
    } catch (Exception e) {
      throw new RuntimeException("Signature verification failed", e);
    }
  }

  /**
   * Returns the encoded byte representation of a public key.
   * Useful for serialization or transport.
   * @param publicKey RSA public key
   * @return Encoded byte array
   */
  public static byte[] encodePublicKey(PublicKey publicKey) {
    return publicKey.getEncoded();
  }
}
