
package peer;

import color.ConsoleColors;
import crypto.AESUtil;
import crypto.DHUtil;
import crypto.RSAUtil;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.SecretKey;

public class KeySender {

  public static SecretKey sessionKey;

  public static void sendKeyToPeer(String host, int port, String username,
      PrivateKey senderPrivateKey, PublicKey receiverRSAPublicKey) {
    try (Socket socket = new Socket(host, port);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream())) {

      // Send identity and RA
      String nonceA = UUID.randomUUID().toString();
      out.writeUTF(username);
      out.writeUTF(nonceA);
      out.flush();
      System.out.println(
          ConsoleColors.PURPLE + "\n──────── Sender Info ────────" + ConsoleColors.RESET);
      System.out.println("🕵️ Identity  : " + username);
      System.out.println("📥 Sent RA   : " + nonceA);

      // Receive RB, Encrypted AES key, Ciphertext, Signature, IV
      String nonceB = in.readUTF();
      byte[] encryptedAESKey = Base64.getDecoder().decode(in.readUTF());
      byte[] ciphertext = Base64.getDecoder().decode(in.readUTF());
      byte[] signature = Base64.getDecoder().decode(in.readUTF());
      byte[] iv = Base64.getDecoder().decode(in.readUTF());

      System.out.println(
          ConsoleColors.PURPLE + "\n──────── Received Response ─────────" + ConsoleColors.RESET);
      System.out.println("📤 Received:");
      System.out.println("   🔹 RB               : " + nonceB);
      System.out.println(
          "   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey));
      System.out.println(
          "   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext));
      System.out.println(
          "   🔹 Signature        : " + Base64.getEncoder().encodeToString(signature));
      System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv));

      // Decrypt AES key and verify signature
      SecretKey aesKey = AESUtil.keyFromBytes(
          RSAUtil.decryptRSA(encryptedAESKey, senderPrivateKey));
      System.out.println(ConsoleColors.PURPLE + "\n──────── Signature Verification   ────────"
          + ConsoleColors.RESET);
      if (DHUtil.verifyWithPublicKey(ciphertext, signature, receiverRSAPublicKey)) {
        System.out.println(ConsoleColors.CYAN + "✅ Signature from receiver verified Successfully."
            + ConsoleColors.RESET);
      } else {
        System.out.println("❌ Signature from receiver invalid. Aborting.");
      }

      // Decrypt and parse message
      String decrypted = AESUtil.decrypt(ciphertext, aesKey, iv);
      String[] parts = decrypted.split("\\|\\|");
      String receivedRA = parts[0];
      String bobDHPubKeyBase64 = parts[1];

      System.out.println(
          ConsoleColors.PURPLE + "\n──────── Nonce Verification   ────────" + ConsoleColors.RESET);
      if (receivedRA.equals(nonceA)) {
        System.out.println("🔐 Sent RA     : " + receivedRA);
        System.out.println("🔐 Received RA : " + receivedRA);
        System.out.println(
            ConsoleColors.BLUE + "✅ Nonce matching. Verified Succeed!" + ConsoleColors.RESET);
      } else {
        System.out.println("❌ NonceA mismatch. Aborting.");
      }

      // Prepare hybrid response {RB || g^a mod p}
      KeyPair aliceKeyPair = DHUtil.generateDHKeyPair();
      String aliceDHPubKeyBase64 = Base64.getEncoder()
          .encodeToString(DHUtil.encodePublicKey(aliceKeyPair.getPublic()));
      String messageToEncrypt = nonceB + "||" + aliceDHPubKeyBase64;
      SecretKey aesKey2 = AESUtil.generateAESKey();
      byte[] iv2 = AESUtil.generateIV();
      byte[] ciphertext2 = AESUtil.encrypt(messageToEncrypt, aesKey2, iv2);
      byte[] signature2 = DHUtil.signWithPrivateKey(ciphertext2, senderPrivateKey);
      byte[] encryptedAESKey2 = RSAUtil.encryptRSA(aesKey2.getEncoded(), receiverRSAPublicKey);

      // Send encrypted response
      out.writeUTF(Base64.getEncoder().encodeToString(encryptedAESKey2));
      out.writeUTF(Base64.getEncoder().encodeToString(ciphertext2));
      out.writeUTF(Base64.getEncoder().encodeToString(signature2));
      out.writeUTF(Base64.getEncoder().encodeToString(iv2));
      out.flush();

      System.out.println(
          ConsoleColors.PURPLE + "\n──────── Sent Response ─────────" + ConsoleColors.RESET);
      System.out.println("📤 Sent:");
      System.out.println(
          "   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey2));
      System.out.println(
          "   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext2));
      System.out.println(
          "   🔹 Signature        : " + Base64.getEncoder().encodeToString(signature2));
      System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv2));

      // Compute shared key
      PublicKey bobDHPubKey = DHUtil.decodePublicKey(Base64.getDecoder().decode(bobDHPubKeyBase64));
      sessionKey = DHUtil.computeSharedSecret(aliceKeyPair.getPrivate(), bobDHPubKey);
      System.out.println(
          "\n" + ConsoleColors.CYAN + "──────── Session Symmetric Key Shared Successfully! ────────"
              + ConsoleColors.RESET);
      System.out.println(
          "🔑 Shared Symmetric Key: " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
      System.out.println("\n" + ConsoleColors.YELLOW + "🛡️ Session Secured. Begin Chatting!\n"
          + ConsoleColors.RESET);

    } catch (Exception e) {
      System.err.println("❌ KeySender DH exchange failed: " + e.getMessage());
      e.printStackTrace();
    }
  }
}