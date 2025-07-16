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

      // Step 1: Send identity and RA
      String nonceA = UUID.randomUUID().toString();
      out.writeUTF(username);
      out.writeUTF(nonceA);
      out.flush();
      System.out.println(ConsoleColors.PURPLE + "\n──────── Sender Info ────────" + ConsoleColors.RESET);
      System.out.println("🕵️ Identity  : " + username);
      System.out.println("📥 Sent RA   : " + nonceA);

      // Step 2: Receive RB, Encrypted AES key, Ciphertext, IV
      String nonceB = in.readUTF();
      byte[] encryptedAESKey = Base64.getDecoder().decode(in.readUTF());
      byte[] ciphertext = Base64.getDecoder().decode(in.readUTF());
      byte[] iv = Base64.getDecoder().decode(in.readUTF());

      System.out.println(ConsoleColors.PURPLE + "\n──────── Received Response ─────────" + ConsoleColors.RESET);
      System.out.println("📤 Received:");
      System.out.println("   🔹 RB               : " + nonceB);
      System.out.println("   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey));
      System.out.println("   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext));
      System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv));

      // Step 3: Decrypt AES key and combined message
      SecretKey aesKey = AESUtil.keyFromBytes(RSAUtil.decryptRSA(encryptedAESKey, senderPrivateKey));
      String decrypted = AESUtil.decrypt(ciphertext, aesKey, iv);
      System.out.println(ConsoleColors.YELLOW + "\n🗝️  Decrypted Message: " + decrypted + ConsoleColors.RESET);

      String[] parts = decrypted.split("\\|\\|");
      if (parts.length != 3) {
        throw new IllegalArgumentException("Invalid decrypted message format (expected 3 parts).");
      }

      String receivedRA = parts[0];
      String bobDHPubKeyBase64 = parts[1];
      byte[] signature = Base64.getDecoder().decode(parts[2]);

      // Step 4: Verify signature
      String messageToVerify = receivedRA + "||" + bobDHPubKeyBase64;
      System.out.println(ConsoleColors.PURPLE + "\n──────── Signature Verification   ────────" + ConsoleColors.RESET);
      if (DHUtil.verifyWithPublicKey(messageToVerify.getBytes(), signature, receiverRSAPublicKey)) {
        System.out.println(ConsoleColors.CYAN + "✅ Signature from receiver verified successfully." + ConsoleColors.RESET);
      } else {
        System.out.println("❌ Signature from receiver invalid. Aborting.");
        return;
      }

      // Step 5: Verify RA (nonce)
      System.out.println(ConsoleColors.PURPLE + "\n──────── Nonce Verification   ────────" + ConsoleColors.RESET);
      if (receivedRA.equals(nonceA)) {
        System.out.println("🔐 Sent RA     : " + nonceA);
        System.out.println("🔐 Received RA : " + receivedRA);
        System.out.println(ConsoleColors.BLUE + "✅ Nonce matching. Verified successfully!" + ConsoleColors.RESET);
      } else {
        System.out.println("❌ NonceA mismatch. Aborting.");
        return;
      }

      // Step 6: Generate DH key pair (g^a mod p), prepare and send signed + encrypted response
      KeyPair aliceKeyPair = DHUtil.generateDHKeyPair();
      String aliceDHPubKeyBase64 = Base64.getEncoder().encodeToString(DHUtil.encodePublicKey(aliceKeyPair.getPublic()));
      String messageToSign = nonceB + "||" + aliceDHPubKeyBase64;

      byte[] signature2 = DHUtil.signWithPrivateKey(messageToSign.getBytes(), senderPrivateKey);
      String combinedMessage = messageToSign + "||" + Base64.getEncoder().encodeToString(signature2);

      SecretKey aesKey2 = AESUtil.generateAESKey();
      byte[] iv2 = AESUtil.generateIV();
      byte[] ciphertext2 = AESUtil.encrypt(combinedMessage, aesKey2, iv2);
      byte[] encryptedAESKey2 = RSAUtil.encryptRSA(aesKey2.getEncoded(), receiverRSAPublicKey);

      out.writeUTF(Base64.getEncoder().encodeToString(encryptedAESKey2));
      out.writeUTF(Base64.getEncoder().encodeToString(ciphertext2));
      out.writeUTF(Base64.getEncoder().encodeToString(iv2));
      out.flush();

      System.out.println(ConsoleColors.PURPLE + "\n──────── Sent Response ─────────" + ConsoleColors.RESET);
      System.out.println("📤 Sent:");
      System.out.println("   🔹 EncryptedAESKey      : " + Base64.getEncoder().encodeToString(encryptedAESKey2));
      System.out.println("   🔹 Ciphertext (embedded): " + Base64.getEncoder().encodeToString(ciphertext2));
      System.out.println("   🔹 IV                   : " + Base64.getEncoder().encodeToString(iv2));
      System.out.println("   🔹 Signature (embedded) : " + Base64.getEncoder().encodeToString(signature2));

      // Step 7: Compute shared session key
      PublicKey bobDHPubKey = DHUtil.decodePublicKey(Base64.getDecoder().decode(bobDHPubKeyBase64));
      sessionKey = DHUtil.computeSharedSecret(aliceKeyPair.getPrivate(), bobDHPubKey);
      System.out.println(ConsoleColors.CYAN + "\n──────── Session Symmetric Key Shared Successfully! ────────" + ConsoleColors.RESET);
      System.out.println("🔑 Shared Symmetric Key: " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
      System.out.println(ConsoleColors.YELLOW + "\n🛡️ Session Secured. Begin Chatting!\n" + ConsoleColors.RESET);

    } catch (Exception e) {
      System.err.println("❌ KeySender DH exchange failed: " + e.getMessage());
      e.printStackTrace();
    }
  }
}
