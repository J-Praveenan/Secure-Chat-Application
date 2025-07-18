// Diffie-Hellman Key Exchange Utilities
package crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DHUtil {

  // Standard 2048-bit MODP group (Group 14) from RFC 3526
  private static final BigInteger P = new BigInteger(
          "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                  + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                  + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                  + "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);

  // Generator value (g = 2)
  private static final BigInteger G = BigInteger.valueOf(2);

  /**
   * Generates a Diffie-Hellman key pair using predefined parameters.
   * @return KeyPair containing DH public and private keys.
   */
  public static KeyPair generateDHKeyPair() throws Exception {
    DHParameterSpec dhParamSpec = new DHParameterSpec(P, G);
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
    keyPairGen.initialize(dhParamSpec);
    return keyPairGen.generateKeyPair();
  }

  /**
   * Decodes a received DH public key from its encoded byte array.
   * @param encoded Encoded public key (X.509 format).
   * @return Decoded PublicKey object.
   */
  public static PublicKey decodePublicKey(byte[] encoded) throws Exception {
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    KeyFactory keyFactory = KeyFactory.getInstance("DH");
    return keyFactory.generatePublic(keySpec);
  }

  /**
   * Computes a shared AES-128 key from the local private key and peer's public key.
   * @param privateKey Local DH private key.
   * @param peerPublicKey Peer DH public key.
   * @return Derived 128-bit AES session key.
   */
  public static SecretKey computeSharedSecret(PrivateKey privateKey, PublicKey peerPublicKey)
          throws Exception {
    KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
    keyAgree.init(privateKey);
    keyAgree.doPhase(peerPublicKey, true);
    byte[] sharedSecret = keyAgree.generateSecret();
    return new SecretKeySpec(sharedSecret, 0, 16, "AES"); // Truncate to 128 bits for AES
  }

  /**
   * Encodes a DH public key into its X.509 byte representation.
   * @param publicKey DH public key.
   * @return Encoded byte array.
   */
  public static byte[] encodePublicKey(PublicKey publicKey) {
    return publicKey.getEncoded();
  }

  /**
   * Signs arbitrary byte data using RSA private key and SHA-256.
   * Typically used to sign DH messages.
   * @param data Data to sign.
   * @param privateKey RSA private key.
   * @return Signature bytes.
   */
  public static byte[] signWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data);
    return signature.sign();
  }

  /**
   * Verifies a digital signature using an RSA public key.
   * @param data Original data that was signed.
   * @param signatureBytes Signature to verify.
   * @param publicKey RSA public key for verification.
   * @return true if signature is valid, false otherwise.
   */
  public static boolean verifyWithPublicKey(byte[] data, byte[] signatureBytes, PublicKey publicKey)
          throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(publicKey);
    signature.update(data);
    return signature.verify(signatureBytes);
  }
}
