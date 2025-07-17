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

  // Generate key pair (private key , public key)
  public static KeyPair generateKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(KEY_SIZE);
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new RuntimeException("RSA Key Generation Failed", e);
    }
  }



  // Encode PublicKey as Base64 String
  public static String getBase64PublicKey(PublicKey pubKey) {
    return Base64.getEncoder().encodeToString(pubKey.getEncoded());
  }

  // Encode PrivateKey as Base64 String
  public static String getBase64PrivateKey(PrivateKey privKey) {
    return Base64.getEncoder().encodeToString(privKey.getEncoded());
  }

  // Convert Base64 public key string to PublicKey object
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

  // Decode Base64 and convert to PrivateKey
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


  // RSA encryption with PublicKey
  public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(data);
  }

  // RSA decryption with PrivateKey
  public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return cipher.doFinal(encryptedData);
  }


  // Sign message using PrivateKey
  public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data.getBytes());
    return signature.sign();
  }

  // Verify signature using PublicKey
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

  public static byte[] encodePublicKey(PublicKey publicKey) {
    return publicKey.getEncoded();
  }




}
