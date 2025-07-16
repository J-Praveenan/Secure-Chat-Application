// Diffie-Hellman Key Exchange Utilities
package crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DHUtil {

  // Prime and generator from standard DH group
  private static final BigInteger P = new BigInteger(
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
          + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
          + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
          + "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
  private static final BigInteger G = BigInteger.valueOf(2);

  public static KeyPair generateDHKeyPair() throws Exception {
    DHParameterSpec dhParamSpec = new DHParameterSpec(P, G);
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
    keyPairGen.initialize(dhParamSpec);
    return keyPairGen.generateKeyPair();
  }

  public static PublicKey decodePublicKey(byte[] encoded) throws Exception {
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    KeyFactory keyFactory = KeyFactory.getInstance("DH");
    return keyFactory.generatePublic(keySpec);
  }

  public static SecretKey computeSharedSecret(PrivateKey privateKey, PublicKey peerPublicKey)
      throws Exception {
    KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
    keyAgree.init(privateKey);
    keyAgree.doPhase(peerPublicKey, true);
    byte[] sharedSecret = keyAgree.generateSecret();
    return new SecretKeySpec(sharedSecret, 0, 16, "AES");
  }

  public static byte[] encodePublicKey(PublicKey publicKey) {
    return publicKey.getEncoded();
  }



  // Sign data with a private key (RSA)
  public static byte[] signWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data);
    return signature.sign();
  }

  // Verify signature with public key (RSA)
  public static boolean verifyWithPublicKey(byte[] data, byte[] signatureBytes, PublicKey publicKey)
      throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(publicKey);
    signature.update(data);
    return signature.verify(signatureBytes);
  }



}
